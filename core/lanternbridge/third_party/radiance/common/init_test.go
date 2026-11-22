package common

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/internal"
	"github.com/getlantern/radiance/log"
)

func TestLoggerPathUsesLogFileInDirectory(t *testing.T) {
	t.Setenv(env.LogToStdout.String(), "false")
	logs := t.TempDir()
	require.Equal(t, filepath.Join(logs, internal.LogFileName), loggerPath(logs))
}

func TestLoggerPathRedirectsToStdout(t *testing.T) {
	t.Setenv(env.LogToStdout.String(), "true")
	require.Equal(t, log.StdoutPath, loggerPath(t.TempDir()))
}

func TestWriteRecoveredPanic_NoLogDir(t *testing.T) {
	t.Cleanup(settings.Reset)
	settings.Reset()
	t.Chdir(t.TempDir())

	func() {
		defer func() { WriteRecoveredPanic("testing", recover()) }()
		panic("boom")
	}()
	assert.NoFileExists(t, internal.CrashLogFileName)
}

func TestSeedLogLevel(t *testing.T) {
	t.Setenv(env.LogLevel.String(), "")

	reinit := func(t *testing.T) {
		t.Helper()
		settings.Reset()
		t.Cleanup(settings.Reset)
		require.NoError(t, settings.InitSettings(t.TempDir()))
	}

	t.Run("seeds a missing value", func(t *testing.T) {
		reinit(t)
		seedLogLevel("info")
		require.Equal(t, "info", settings.GetString(settings.LogLevelKey))
	})

	t.Run("demotes a stale trace", func(t *testing.T) {
		reinit(t)
		require.NoError(t, settings.Set(settings.LogLevelKey, "trace"))
		seedLogLevel("info")
		require.Equal(t, "info", settings.GetString(settings.LogLevelKey))
	})

	t.Run("keeps a persisted non-trace value", func(t *testing.T) {
		reinit(t)
		require.NoError(t, settings.Set(settings.LogLevelKey, "debug"))
		seedLogLevel("info")
		require.Equal(t, "debug", settings.GetString(settings.LogLevelKey))
	})

	t.Run("a trace build keeps a persisted trace", func(t *testing.T) {
		reinit(t)
		require.NoError(t, settings.Set(settings.LogLevelKey, "trace"))
		seedLogLevel("trace")
		require.Equal(t, "trace", settings.GetString(settings.LogLevelKey))
	})

	t.Run("env override wins and is persisted", func(t *testing.T) {
		reinit(t)
		t.Setenv(env.LogLevel.String(), "warn")
		require.NoError(t, settings.Set(settings.LogLevelKey, "trace"))
		seedLogLevel("info")
		require.Equal(t, "warn", settings.GetString(settings.LogLevelKey))
	})
}
