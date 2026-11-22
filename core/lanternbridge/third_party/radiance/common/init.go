// Package common contains common initialization code and utilities for the Radiance application.
package common

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/fileperm"
	"github.com/getlantern/radiance/common/reporting"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/internal"
	"github.com/getlantern/radiance/log"
)

var (
	initialized atomic.Bool
)

func Env() string {
	return strings.ToLower(env.GetString(env.ENV))
}

// Prod returns true if the application is running in production environment.
// Treating ENV == "" as production is intentional: if RADIANCE_ENV is unset,
// we default to production mode to ensure the application runs with safe, non-debug settings.
func Prod() bool {
	e := Env()
	return e == "production" || e == "prod" || e == ""
}

// Dev returns true if the application is running in development environment.
func Dev() bool {
	e := Env()
	return e == "development" || e == "dev"
}

// Stage returns true if the application is running in staging environment.
func Stage() bool {
	e := Env()
	return e == "stage" || e == "staging"
}

func init() {
	if env.GetBool(env.Testing) {
		slog.SetDefault(log.NoOpLogger())
		slog.SetLogLoggerLevel(log.Disable)
	}
}

// Init initializes the common components of the application. This includes setting up the directories
// for data and logs, initializing the logger, and setting up reporting.
func Init(dataDir, logDir, logLevel string) (err error) {
	slog.Info("Initializing common package")
	if initialized.Swap(true) {
		return nil
	}
	defer func() {
		if err != nil {
			initialized.Store(false)
		}
	}()

	if v, ok := env.Get(env.AppVersion); ok && v != "" {
		Version = v
		slog.Info("Version overridden via RADIANCE_VERSION", "version", Version)
	}
	reporting.Init(GetVersion())
	data, logs, err := setupDirectories(dataDir, logDir)
	if err != nil {
		return fmt.Errorf("failed to setup directories: %w", err)
	}

	if err = settings.InitSettings(data); err != nil {
		return fmt.Errorf("failed to initialize settings: %w", err)
	}

	settings.Patch(settings.Settings{settings.DataPathKey: data, settings.LogPathKey: logs})
	seedLogLevel(logLevel)

	logger := log.NewLogger(log.Config{
		LogPath: loggerPath(logs),
		Level:   logLevel,
		Prod:    Prod(),
	})
	slog.SetDefault(logger)

	slog.Info("Using data and log directories", "dataDir", data, "logDir", logs)
	createCrashReporter()
	logBuildInfo()
	return nil
}

// seedLogLevel reconciles the persisted log level with the configured one.
// The persisted value outranks the configured one, and builds through
// v10.0.x persisted "trace", so without the demotion an upgraded install
// logs at trace forever.
func seedLogLevel(configured string) {
	if v := env.GetString(env.LogLevel); v != "" {
		settings.Set(settings.LogLevelKey, v)
		return
	}
	if configured == "" {
		return
	}
	settings.SetIfAbsent(settings.LogLevelKey, configured)
	if configured != "trace" {
		settings.ReplaceString(settings.LogLevelKey, "trace", configured)
	}
}

// extraLoadBearingDeps are non-getlantern modules whose linked versions are
// surfaced at Info alongside all github.com/getlantern/* deps (see
// isLoadBearing). A stale one — a build resolving deps differently than go.mod
// declares — has shipped user-facing regressions. The full dependency list is
// logged at Debug.
var extraLoadBearingDeps = map[string]struct{}{
	"github.com/sagernet/sing-box": {},
}

func isLoadBearing(path string) bool {
	if strings.HasPrefix(path, "github.com/getlantern/") {
		return true
	}
	_, ok := extraLoadBearingDeps[path]
	return ok
}

// logBuildInfo records the build's identity (version, build time, commit) and the
// dep versions actually linked into the binary, in every build — not just Dev — so
// a shipped binary is self-describing and a stale-cache build is visible in logs
// rather than silent.
func logBuildInfo() {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		slog.Info("build", "version", Version, "buildTime", BuildTime, "commit", Commit, "note", "no build info")
		return
	}
	slog.Info("build",
		"version", Version,
		"buildTime", BuildTime,
		"commit", Commit,
		"goVersion", bi.GoVersion,
		"mainModule", bi.Main.Path+"@"+bi.Main.Version,
	)
	for _, dep := range bi.Deps {
		attrs := []any{"path", dep.Path, "version", dep.Version}
		if dep.Replace != nil {
			// A replace directive means the linked module is not the declared one —
			// the exact mismatch this banner exists to surface.
			replacement := dep.Replace.Path
			if dep.Replace.Version != "" { // local-directory replaces have no version
				replacement += "@" + dep.Replace.Version
			} else if filepath.IsAbs(replacement) {
				// These logs ship in support tickets and crash reports; don't leak
				// build-host paths (usernames, home dirs). Relative replaces stay.
				replacement = "(local directory)"
			}
			attrs = append(attrs, "replacedBy", replacement)
		}
		if isLoadBearing(dep.Path) {
			slog.Info("build dep", attrs...)
		}
		slog.Debug("build dep", attrs...)
	}
}

func openCrashLog() (*os.File, error) {
	path := filepath.Join(settings.GetString(settings.LogPathKey), internal.CrashLogFileName)
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileperm.File)
}

func createCrashReporter() {
	f, err := openCrashLog()
	if err != nil {
		slog.Error("Failed to open crash log file", "error", err)
	} else {
		debug.SetCrashOutput(f, debug.CrashOptions{})
		// We can close f after SetCrashOutput because it duplicates the file descriptor.
		f.Close()
	}
}

// WriteRecoveredPanic appends a recovered panic and the calling goroutine's stack to the crash log.
// The stack includes the panicking frames only while the recovering deferred call is still running.
// Nothing is written when the log directory is unset.
func WriteRecoveredPanic(operation string, recovered any) {
	if settings.GetString(settings.LogPathKey) == "" {
		return
	}
	f, err := openCrashLog()
	if err != nil {
		slog.Error("Failed to open crash log file", "error", err)
		return
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s recovered panic %s: %v\n%s\n",
		time.Now().UTC().Format(time.RFC3339Nano), operation, recovered, debug.Stack())
	if err != nil {
		slog.Error("Failed to write recovered panic to crash log", "error", err)
	}
}

func loggerPath(logs string) string {
	if env.GetBool(env.LogToStdout) {
		return log.StdoutPath
	}
	return filepath.Join(logs, internal.LogFileName)
}

// setupDirectories creates the data and logs directories, and needed subdirectories if they do
// not exist. If data or logs are the empty string, it will use the user's config directory retrieved
// from the OS.
func setupDirectories(data, logs string) (dataDir, logDir string, err error) {
	if path := env.GetString(env.DataPath); path != "" {
		data = path
	} else if data == "" {
		data = internal.DefaultDataPath()
	}
	if path := env.GetString(env.LogPath); path != "" {
		logs = path
	} else if logs == "" {
		logs = internal.DefaultLogPath()
	}
	// Honor the caller's path as-is. A previous version of this function
	// unconditionally appended /data and /logs suffixes here even when the
	// caller passed a fully-resolved path (e.g. Android passes
	// <app.dataDir>/.lantern). That broke upgrade continuity: v9.0.x had
	// written settings.json under <caller-path>/, while v9.1.x reads from
	// <caller-path>/data/, so every existing install lost its persisted
	// user_id, device_id, jwt token, and user_level on upgrade — surfacing
	// as "Pro is suddenly expired after the update."
	data, _ = filepath.Abs(data)
	logs, _ = filepath.Abs(logs)
	for _, path := range []string{data, logs} {
		if err := os.MkdirAll(path, 0755); err != nil {
			return data, logs, fmt.Errorf("failed to create directory %s: %w", path, err)
		}
	}
	return data, logs, nil
}
