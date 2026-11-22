package backend

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Xuanwo/go-locale"
	"github.com/getlantern/radiance/common/settings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartupSettingsPreserveSavedPreferences(t *testing.T) {
	for _, consent := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[consent], func(t *testing.T) {
			settings.Reset()
			t.Cleanup(settings.Reset)
			dir := t.TempDir()
			require.NoError(t, settings.InitSettings(dir))
			require.NoError(t, settings.Patch(settings.Settings{
				settings.DeviceIDKey:  "saved-device-id",
				settings.LocaleKey:    "fa-IR",
				settings.TelemetryKey: consent,
				settings.TimeZoneKey:  "Asia/Tehran",
			}))

			for range 2 {
				startup := startupSettings(Options{PreserveTelemetryConsent: true})
				assert.NotContains(t, startup, settings.TelemetryKey)
				require.NoError(t, settings.Patch(startup))
				settings.Reset()
				require.NoError(t, settings.InitSettings(dir))
				assert.Equal(t, "saved-device-id", settings.GetString(settings.DeviceIDKey))
				assert.Equal(t, "fa-IR", settings.GetString(settings.LocaleKey))
				assert.Equal(t, consent, settings.GetBool(settings.TelemetryKey))
				assert.Equal(t, "Asia/Tehran", settings.GetString(settings.TimeZoneKey))
			}
		})
	}
}

func TestStartupSettingsExplicitPreferencesOverrideSaved(t *testing.T) {
	for _, consent := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[consent], func(t *testing.T) {
			settings.Reset()
			t.Cleanup(settings.Reset)
			require.NoError(t, settings.InitSettings(t.TempDir()))
			require.NoError(t, settings.Patch(settings.Settings{
				settings.DeviceIDKey:  "saved-device-id",
				settings.LocaleKey:    "fa-IR",
				settings.TelemetryKey: !consent,
				settings.TimeZoneKey:  "Asia/Tehran",
			}))

			require.NoError(t, settings.Patch(startupSettings(Options{
				Locale:           "en-US",
				TelemetryConsent: consent,
				TimeZone:         "America/Los_Angeles",
			})))
			assert.Equal(t, "en-US", settings.GetString(settings.LocaleKey))
			assert.Equal(t, consent, settings.GetBool(settings.TelemetryKey))
			assert.Equal(t, "America/Los_Angeles", settings.GetString(settings.TimeZoneKey))
		})
	}
}

func TestStartupSettingsDetectsLocaleWhenMissing(t *testing.T) {
	settings.Reset()
	t.Cleanup(settings.Reset)
	require.NoError(t, settings.InitSettings(t.TempDir()))
	require.NoError(t, settings.Set(settings.DeviceIDKey, "saved-device-id"))
	require.False(t, settings.Exists(settings.LocaleKey))
	want := "en-US"
	if tag, err := locale.Detect(); err == nil {
		want = tag.String()
	}
	require.NoError(t, settings.Patch(startupSettings(Options{PreserveTelemetryConsent: true})))
	assert.Equal(t, want, settings.GetString(settings.LocaleKey))
	assert.False(t, settings.Exists(settings.TelemetryKey))
}

func TestStartupSettingsGeneratesMissingDesktopDeviceID(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "android" || runtime.GOOS == "ios" {
		t.Skip("device ID generation uses platform state outside the fixture")
	}
	settings.Reset()
	t.Cleanup(settings.Reset)
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	require.NoError(t, settings.InitSettings(dir))
	require.NoError(t, settings.Set(settings.DataPathKey, dir))

	require.NoError(t, settings.Patch(startupSettings(Options{})))
	deviceID := settings.GetString(settings.DeviceIDKey)
	require.NotEmpty(t, deviceID)
	stored, err := os.ReadFile(filepath.Join(dir, ".lanternsecrets", ".deviceid"))
	require.NoError(t, err)
	assert.Equal(t, deviceID, string(stored))
	settings.Reset()
	require.NoError(t, settings.InitSettings(dir))
	require.NoError(t, settings.Patch(startupSettings(Options{DeviceID: "ignored-desktop-option"})))
	assert.Equal(t, deviceID, settings.GetString(settings.DeviceIDKey))
}
