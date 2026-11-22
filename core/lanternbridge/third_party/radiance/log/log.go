package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/fileperm"
	"github.com/getlantern/radiance/common/settings"

	lsync "github.com/getlantern/common/sync"
)

const (
	// slog does not define trace and fatal levels, so we define them here.
	LevelTrace = slog.LevelDebug - 4
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
	LevelFatal = slog.LevelError + 4
	LevelPanic = slog.LevelError + 8

	Disable = slog.LevelInfo + 1000 // A level that disables logging, used for testing or no-op logger.
)

// StdoutPath makes Config.LogPath write to stdout instead of a file.
// No file is opened and no rotation is performed.
const StdoutPath = "stdout"

type Config struct {
	// LogPath is the full path to the log file, or [StdoutPath].
	LogPath string
	// Level is the log level string (e.g., "info", "debug").
	Level string
	// Prod indicates whether the application is running in production mode.
	Prod bool
	// DisablePublisher indicates whether to disable the log publisher which is used for real-time
	// log streaming.
	DisablePublisher bool
}

// NewLogger returns a configured logger that writes to a rotating file and
// optionally stdout, or to stdout only when LogPath is StdoutPath.
//
// When env.Testing is set, a no-op logger is returned before any file is created. A "disable"
// level is different: it only filters records, so the log file is still created.
//
// Top-level "time" and "level" attributes whose values are not, respectively, a
// time.Time or slog.Level are emitted as "attr.time" and "attr.level".
//
// Attribute values are redacted when their key, or an enclosing group's key, names a
// credential or user identifier, or when they are not errors, times, scalars, slices
// or arrays of non-byte scalars, or maps of scalars. Map entries are redacted by the
// same key rule. The message, error values and strings, including slice, array and
// map elements, have URL queries stripped and the values of secret JSON fields
// redacted. Such text over a size limit that may hold a secret field is replaced
// whole.
func NewLogger(cfg Config) *slog.Logger {
	if env.GetBool(env.Testing) {
		return NoOpLogger()
	}
	level := settings.GetString(settings.LogLevelKey)
	if level == "" {
		level = env.GetString(env.LogLevel)
	}
	if level == "" && cfg.Level != "" {
		level = cfg.Level
	}
	slevel, err := ParseLogLevel(level)
	if err != nil {
		slog.Warn("Failed to parse log level", "error", err)
	}
	slog.SetLogLoggerLevel(slevel)
	leveler := settingsLeveler{fallback: slevel}

	isWindows := runtime.GOOS == "windows"
	toStdout := cfg.LogPath == StdoutPath

	loggingToStdOut := true
	var logWriter io.Writer
	if toStdout {
		logWriter = os.Stdout
	} else {
		// Pre-create the file so the intended platform-specific permissions apply
		// before lumberjack reuses it.
		f, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, fileperm.File)
		if err != nil {
			slog.Warn("Failed to pre-create log file", "error", err, "path", cfg.LogPath)
		} else {
			f.Close()
		}

		logRotator := &lumberjack.Logger{
			Filename:   cfg.LogPath,
			MaxSize:    25, // Rotate log when it reaches 25 MB
			MaxBackups: 2,
			MaxAge:     30, // Retain old log files for up to 30 days
			Compress:   cfg.Prod,
		}

		switch {
		case env.GetBool(env.DisableStdout):
			logWriter = logRotator
			loggingToStdOut = false
		case isWindows && cfg.Prod:
			// Windows services silently stop writing the file when the same logger also writes
			// stdout, so prod on Windows is file-only.
			logWriter = logRotator
			loggingToStdOut = false
		default:
			logWriter = io.MultiWriter(os.Stdout, logRotator)
		}
	}
	if !cfg.DisablePublisher {
		logWriter = io.MultiWriter(logWriter, Publisher())
	}
	logWriter = newRedactingWriter(logWriter)
	logger := slog.New(newRootHandler(logWriter, leveler))
	if toStdout {
		fmt.Printf("Logging to stdout only, level: %s\n", FormatLogLevel(slevel))
	} else if !loggingToStdOut {
		if isWindows {
			fmt.Printf("Logging to file only on Windows prod -- run with RADIANCE_ENV=dev to enable stdout path: %s, level: %s\n", cfg.LogPath, FormatLogLevel(slevel))
		} else {
			fmt.Printf("Logging to file only -- RADIANCE_DISABLE_STDOUT_LOG is set path: %s, level: %s\n", cfg.LogPath, FormatLogLevel(slevel))
		}
	} else {
		fmt.Printf("Logging to file and stdout path: %s, level: %s\n", cfg.LogPath, FormatLogLevel(slevel))
	}
	return logger
}

func newRootHandler(w io.Writer, level slog.Leveler) *Handler {
	return &Handler{Handler: newTeeHandler(newHandler(w, level)), w: w}
}

func newHandler(w io.Writer, level slog.Leveler) slog.Handler {
	return newSourceHandler(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: replaceLogAttr,
	}))
}

func replaceLogAttr(groups []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case slog.TimeKey:
		if t, ok := a.Value.Any().(time.Time); ok {
			a.Value = slog.StringValue(t.UTC().Format("2006-01-02 15:04:05.000 UTC"))
			return a
		} else if len(groups) == 0 {
			a.Key = "attr." + slog.TimeKey
		}
	case slog.LevelKey:
		// slog renders custom levels like trace as "DEBUG-4"; FormatLogLevel gives them real names.
		if level, ok := a.Value.Any().(slog.Level); ok {
			a.Value = slog.StringValue(FormatLogLevel(level))
			return a
		} else if len(groups) == 0 {
			a.Key = "attr." + slog.LevelKey
		}
	}
	return redactAttr(groups, a)
}

type Handler struct {
	slog.Handler
	w io.Writer
}

func (h *Handler) Writer() io.Writer {
	return h.w
}

// sourceHandler adds a cached, human-readable source attribute derived from the
// record PC. This keeps source formatting out of ReplaceAttr and avoids
// recomputing it for repeated call sites.
type sourceHandler struct {
	slog.Handler
	cache *lsync.TypedMap[uintptr, slog.Attr]
}

func newSourceHandler(next slog.Handler) slog.Handler {
	return &sourceHandler{
		Handler: next,
		cache:   new(lsync.TypedMap[uintptr, slog.Attr]),
	}
}

func (h *sourceHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.PC == 0 {
		return h.Handler.Handle(ctx, r)
	}

	r = r.Clone()
	r.AddAttrs(h.sourceAttr(r.PC))
	return h.Handler.Handle(ctx, r)
}

func (h *sourceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h.withHandler(h.Handler.WithAttrs(attrs))
}

func (h *sourceHandler) WithGroup(name string) slog.Handler {
	return h.withHandler(h.Handler.WithGroup(name))
}

func (h *sourceHandler) withHandler(next slog.Handler) slog.Handler {
	return &sourceHandler{
		Handler: next,
		cache:   h.cache,
	}
}

func (h *sourceHandler) sourceAttr(pc uintptr) slog.Attr {
	if attr, ok := h.cache.Load(pc); ok {
		return attr
	}

	pcs := [1]uintptr{pc}
	frame, _ := runtime.CallersFrames(pcs[:]).Next()

	attr := formatSource(frame.Function, frame.File, frame.Line)
	h.cache.Store(pc, attr)
	return attr
}

func formatSource(function, file string, line int) slog.Attr {
	pkg, fn, ok := parseSourceFunction(function)
	if !ok {
		return slog.String(slog.SourceKey, fmt.Sprintf("%s:%d", filepath.Base(file), line))
	}

	return slog.Group("",
		slog.String("pkg", pkg),
		slog.Group("source",
			slog.String("func", fn),
			slog.String("file", fmt.Sprintf("%s:%d", trimSourceFile(file, pkg), line)),
		),
	)
}

// parseSourceFunction splits a runtime function symbol into a package label and
// a function name. The label is the symbol's third slash-separated segment, so
// for a github.com/org/repo/leaf path it is the repo name, not the leaf package:
//
//   - "github.com/org/repo/leaf.Func"           → "repo", "Func"
//   - "github.com/org/repo/leaf.(*Type).Method" → "repo", "(*Type).Method"
//
// ok is false when the symbol has fewer than three segments.
func parseSourceFunction(symbol string) (pkg string, fn string, ok bool) {
	pathParts := strings.SplitN(symbol, "/", 4)

	switch len(pathParts) {
	case 3:
		pkg, fn, ok = strings.Cut(pathParts[2], ".")
		return pkg, fn, ok && pkg != "" && fn != ""
	case 4:
		pkg = pathParts[2]
		if pkg == "" {
			return "", "", false
		}

		_, fn, ok = strings.Cut(pathParts[3], ".")
		return pkg, fn, ok && fn != ""
	default:
		return "", "", false
	}
}

func trimSourceFile(file, pkg string) string {
	if _, after, found := strings.Cut(file, pkg+"/"); found && after != "" {
		return after
	}
	return filepath.Base(file)
}

// settingsLeveler reads the current log level from settings on each call,
// so changes to settings.LogLevelKey take effect without rebuilding the logger.
type settingsLeveler struct {
	fallback slog.Level
}

func (s settingsLeveler) Level() slog.Level {
	if v := settings.GetString(settings.LogLevelKey); v != "" {
		if lvl, err := ParseLogLevel(v); err == nil {
			return lvl
		}
	}
	return s.fallback
}

// ParseLogLevel parses a string representation of a log level and returns the corresponding slog.Level.
// If the level is not recognized, it returns LevelInfo.
func ParseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	case "fatal":
		return LevelFatal, nil
	case "panic":
		return LevelPanic, nil
	case "disable", "none", "off":
		return Disable, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level: %s", level)
	}
}

func FormatLogLevel(level slog.Level) string {
	switch {
	case level < LevelDebug:
		return "TRACE"
	case level < LevelInfo:
		return "DEBUG"
	case level < LevelWarn:
		return "INFO"
	case level < LevelError:
		return "WARN"
	case level < LevelFatal:
		return "ERROR"
	case level < LevelPanic:
		return "FATAL"
	default:
		return "PANIC"
	}
}

func NoOpLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: Disable,
	}))
}
