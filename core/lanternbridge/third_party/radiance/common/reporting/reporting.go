// Package reporting provides slog-backed hooks for crash and panic reporting.
package reporting

import (
	"context"
	"log/slog"
	"runtime/debug"

	"github.com/getlantern/radiance/log"
)

// Init records the build version in the log.
func Init(version string) {
	slog.Info("reporting initialized", "version", version)
}

// PanicListener logs msg with the captured stack at [log.LevelPanic].
func PanicListener(msg string) {
	slog.Log(context.Background(), log.LevelPanic, msg,
		"stack", string(debug.Stack()),
	)
}
