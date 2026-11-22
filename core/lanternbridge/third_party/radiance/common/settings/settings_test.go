package settings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/knadh/koanf/v2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/env"
)

func TestWindowsCrossDirCandidates(t *testing.T) {
	t.Run("returns nil on non-Windows", func(t *testing.T) {
		// On macOS/Linux the function must short-circuit regardless of
		// %PUBLIC% being set — this is the implicit GOOS gate that keeps
		// the cross-dir scan from misfiring elsewhere.
		if runtime.GOOS == "windows" {
			t.Skip("test only meaningful on non-Windows hosts")
		}
		t.Setenv("PUBLIC", t.TempDir())
		assert.Nil(t, windowsCrossDirCandidates("/some/dir"))
	})

	t.Run("returns nil when %PUBLIC% is unset", func(t *testing.T) {
		t.Setenv("PUBLIC", "")
		assert.Nil(t, windowsCrossDirCandidates("/some/dir"))
	})

	t.Run("readWindowsCrossDirCandidates picks up local.json", func(t *testing.T) {
		dir := t.TempDir()
		body := []byte(`{"user_level":"pro","user_id":1}`)
		require.NoError(t, os.WriteFile(filepath.Join(dir, legacySettingsFileName), body, 0o644))

		cs := readWindowsCrossDirCandidates(dir)
		require.Len(t, cs, 1, "expected one candidate when only local.json exists")
		assert.True(t, cs[0].exists)
		assert.Equal(t, body, cs[0].contents)
		assert.Contains(t, cs[0].label, "v9.0.x Windows", "label must identify the cross-dir source")
	})

	t.Run("readWindowsCrossDirCandidates picks up both local.json and settings.json", func(t *testing.T) {
		dir := t.TempDir()
		local := []byte(`{"user_level":"pro","user_id":1}`)
		canon := []byte(`{"user_level":"expired","user_id":2}`)
		require.NoError(t, os.WriteFile(filepath.Join(dir, legacySettingsFileName), local, 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, settingsFileName), canon, 0o644))

		cs := readWindowsCrossDirCandidates(dir)
		require.Len(t, cs, 2, "both filenames should be returned when both exist")
		// local.json must come first — it's the actual v9.0.x name; the
		// settings.json fallback is for users who got renamed by a
		// partial earlier upgrade.
		assert.Equal(t, local, cs[0].contents, "local.json must be first")
		assert.Equal(t, canon, cs[1].contents, "settings.json fallback must be second")
	})

	t.Run("readWindowsCrossDirCandidates returns empty when dir is empty", func(t *testing.T) {
		assert.Empty(t, readWindowsCrossDirCandidates(t.TempDir()))
	})

	t.Run("samePathWindows is case-insensitive", func(t *testing.T) {
		// This is the load-bearing property of the guard — NTFS is
		// case-insensitive by default, so callers may supply equivalent
		// paths with different casing. Portable across OSes.
		assert.True(t, samePathWindows("/tmp/foo", "/tmp/FOO"))
		assert.True(t, samePathWindows(`C:\Users\Public`, `c:\users\public`))
		assert.False(t, samePathWindows("/tmp/foo", "/tmp/bar"))
	})

	t.Run("samePathWindows normalizes Windows separators (Windows only)", func(t *testing.T) {
		// On Windows, filepath.Clean folds `\` and `/` into the native
		// separator and strips trailing slashes. On Unix-style hosts
		// these characters are treated literally, so the assertion is
		// meaningless off-Windows. The function itself is only called
		// from windowsCrossDirCandidates, which short-circuits unless
		// GOOS=="windows" — i.e. the cases below only matter in the
		// environment they're exercised.
		if runtime.GOOS != "windows" {
			t.Skip("Windows-only path-cleaning semantics")
		}
		assert.True(t, samePathWindows(`C:\Users\Public\Lantern\data`, `C:/Users/Public/Lantern/data`))
		assert.True(t, samePathWindows(`C:\Users\Public\Lantern\data\`, `C:\Users\Public\Lantern\data`))
		assert.False(t, samePathWindows(`C:\Users\Public\Lantern\data`, `C:\Users\Public\Lantern\other`))
	})
}

func TestInitSettings(t *testing.T) {
	t.Run("existing valid config file", func(t *testing.T) {
		tempDir := t.TempDir()
		path := filepath.Join(tempDir, settingsFileName)
		content := []byte(`{"locale": "en-US", "country_code": "US"}`)
		require.NoError(t, os.WriteFile(path, content, 0644), "failed to create test config file")

		require.NoError(t, InitSettings(tempDir), "failed to initialize settings")
		assert.Equal(t, "en-US", Get(LocaleKey))
		assert.Equal(t, "US", Get(CountryCodeKey))
	})

	t.Run("invalid config file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), settingsFileName)
		content := []byte(`{invalid json}`)
		require.NoError(t, os.WriteFile(path, content, 0644), "failed to create test config file")
		require.Error(t, loadInto(koanf.New("."), path), "expected error for invalid config file")
	})

	t.Run("invalid config file recovers", func(t *testing.T) {
		Reset()
		t.Cleanup(Reset)
		tempDir := t.TempDir()
		path := filepath.Join(tempDir, settingsFileName)
		require.NoError(t, os.WriteFile(path, []byte(`{invalid json}`), 0644))

		require.NoError(t, InitSettings(tempDir), "an invalid settings file must not block initialization")

		invalidPath := filepath.Join(tempDir, settingsInvalidFileName)
		assert.FileExists(t, invalidPath, "the invalid file must be preserved for diagnostics")
		assert.NoError(t, loadInto(koanf.New("."), path), "settings.json must be rewritten with a parseable default")
	})
}

func TestMigrateLegacySettingsIfNeeded(t *testing.T) {
	// Redirect the OS-specific pre-9.x YAML lookup to nowhere by
	// default so individual tests don't pick up the host machine's
	// actual ~/Library/Application Support/Lantern/settings.yaml or
	// equivalent. Sub-tests that exercise the YAML path opt in by
	// pointing the function at their tempDir.
	prevYAMLPath := legacyYAMLPathFn
	legacyYAMLPathFn = func(string) (string, string) { return "", "" }
	t.Cleanup(func() { legacyYAMLPathFn = prevYAMLPath })

	// Same treatment for the Windows v9.0.x cross-dir lookup: default
	// to nothing so tests don't accidentally pick up a real
	// %PUBLIC%\Lantern\data on a developer's Windows machine. Tests that
	// exercise this path opt in.
	prevWinCrossDir := windowsCrossDirCandidatesFn
	windowsCrossDirCandidatesFn = func(string) []candidateSource { return nil }
	t.Cleanup(func() { windowsCrossDirCandidatesFn = prevWinCrossDir })

	writeNested := func(t *testing.T, dir string, contents []byte) {
		t.Helper()
		nd := filepath.Join(dir, "data")
		require.NoError(t, os.MkdirAll(nd, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(nd, settingsFileName), contents, 0o644))
	}
	writeLegacy := func(t *testing.T, dir string, contents []byte) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, legacySettingsFileName), contents, 0o644))
	}

	t.Run("v9.0.x local.json recovered when canonical is missing (Derek's failing case)", func(t *testing.T) {
		// User upgraded from v9.0.x straight to the fixed build. v9.0.x wrote
		// to <dataDir>/local.json; canonical settings.json doesn't exist;
		// no v9.1.x nested file. The fix must read local.json so Pro survives.
		tempDir := t.TempDir()
		want := []byte(`{"user_id": 3580849, "user_level": "pro", "token": "abc"}`)
		writeLegacy(t, tempDir, want)

		canonical := filepath.Join(tempDir, settingsFileName)
		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, want, got, "v9.0.x local.json should be migrated to canonical")
	})

	t.Run("v9.1.x nested file recovered when canonical is missing", func(t *testing.T) {
		tempDir := t.TempDir()
		want := []byte(`{"user_id": 135809562, "user_level": "pro", "device_id": "abc"}`)
		writeNested(t, tempDir, want)

		canonical := filepath.Join(tempDir, settingsFileName)
		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, want, got, "v9.1.x nested file should be migrated to canonical")
	})

	t.Run("v9.0.x local.json wins over v9.1.x expired nested", func(t *testing.T) {
		// Upgrade chain v9.0.x → v9.1.x → fix: legacy has pro, nested has
		// expired (because v9.1.x lost the user_id). Migration must pick
		// legacy so Pro survives.
		tempDir := t.TempDir()
		canonical := filepath.Join(tempDir, settingsFileName)
		legacyPro := []byte(`{"user_id": 1, "user_level": "pro"}`)
		writeLegacy(t, tempDir, legacyPro)
		writeNested(t, tempDir, []byte(`{"user_id": 999, "user_level": "expired"}`))

		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, legacyPro, got, "legacy local.json with pro should beat nested expired")
	})

	t.Run("canonical-pro wins over nested-expired", func(t *testing.T) {
		tempDir := t.TempDir()
		canonical := filepath.Join(tempDir, settingsFileName)
		canonicalPro := []byte(`{"user_id": 1, "user_level": "pro"}`)
		require.NoError(t, os.WriteFile(canonical, canonicalPro, 0o644))
		writeNested(t, tempDir, []byte(`{"user_id": 999, "user_level": "expired"}`))

		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, canonicalPro, got, "canonical-pro should survive")
	})

	t.Run("canonical expired account survives nested Pro recovery", func(t *testing.T) {
		tempDir := t.TempDir()
		canonical := filepath.Join(tempDir, settingsFileName)
		canonicalContents := []byte(`{"user_id": 1, "user_level": "expired"}`)
		require.NoError(t, os.WriteFile(canonical, canonicalContents, 0o644))
		writeLegacy(t, tempDir, []byte(`{"user_id": 1, "user_level": "expired"}`))
		nestedPro := []byte(`{"user_id": 2, "user_level": "pro"}`)
		writeNested(t, tempDir, nestedPro)

		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, canonicalContents, got)
	})

	t.Run("all-pro: canonical wins (most recent deliberate state)", func(t *testing.T) {
		tempDir := t.TempDir()
		canonical := filepath.Join(tempDir, settingsFileName)
		canonicalContents := []byte(`{"user_id": 1, "user_level": "pro"}`)
		require.NoError(t, os.WriteFile(canonical, canonicalContents, 0o644))
		writeLegacy(t, tempDir, []byte(`{"user_id": 2, "user_level": "pro"}`))
		writeNested(t, tempDir, []byte(`{"user_id": 3, "user_level": "pro"}`))

		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, canonicalContents, got, "canonical preferred when all have pro")
	})

	t.Run("canonical free account survives stale Pro recovery files", func(t *testing.T) {
		dir := t.TempDir()
		canonical := filepath.Join(dir, settingsFileName)
		adopted := []byte(`{"user_id":42,"user_level":"free","token":"adopted-token"}`)
		require.NoError(t, os.WriteFile(canonical, adopted, 0600))
		stalePro := []byte(`{"user_id":1,"user_level":"pro","token":"stale-token"}`)
		writeLegacy(t, dir, stalePro)
		writeNested(t, dir, stalePro)

		migrateLegacySettingsIfNeeded(dir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, adopted, got)
	})

	t.Run("logged out canonical settings survive stale Pro recovery files", func(t *testing.T) {
		dir := t.TempDir()
		canonical := filepath.Join(dir, settingsFileName)
		require.NoError(t, os.WriteFile(canonical, []byte(`{}`), 0600))
		writeLegacy(t, dir, []byte(`{"user_id":1,"user_level":"pro","token":"stale-token"}`))

		migrateLegacySettingsIfNeeded(dir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.JSONEq(t, `{}`, string(got))
	})

	t.Run("invalid canonical settings recover a valid free account", func(t *testing.T) {
		for _, invalid := range []string{`{invalid}`, `null`, `[]`, `{} {}`} {
			t.Run(invalid, func(t *testing.T) {
				dir := t.TempDir()
				canonical := filepath.Join(dir, settingsFileName)
				require.NoError(t, os.WriteFile(canonical, []byte(invalid), 0600))
				legacy := []byte(`{"user_id":42,"user_level":"free","token":"current-token"}`)
				writeLegacy(t, dir, legacy)

				migrateLegacySettingsIfNeeded(dir, canonical)

				got, err := os.ReadFile(canonical)
				require.NoError(t, err)
				assert.Equal(t, legacy, got)
			})
		}
	})

	t.Run("malformed legacy settings do not hide a valid nested account", func(t *testing.T) {
		dir := t.TempDir()
		canonical := filepath.Join(dir, settingsFileName)
		writeLegacy(t, dir, []byte(`{invalid}`))
		nested := []byte(`{"user_id":42,"user_level":"free"}`)
		writeNested(t, dir, nested)

		migrateLegacySettingsIfNeeded(dir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, nested, got)
	})

	t.Run("none have pro: legacy wins over nested when canonical missing", func(t *testing.T) {
		// User identifiers must survive even when Pro state is non-pro,
		// to keep the device registration intact server-side.
		tempDir := t.TempDir()
		canonical := filepath.Join(tempDir, settingsFileName)
		legacyContents := []byte(`{"user_id": 1, "user_level": "free", "token": "abc"}`)
		writeLegacy(t, tempDir, legacyContents)
		writeNested(t, tempDir, []byte(`{"user_id": 2, "user_level": "free", "token": "xyz"}`))

		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, legacyContents, got, "legacy preferred over nested when canonical missing and neither has pro")
	})

	t.Run("nothing on disk is a no-op", func(t *testing.T) {
		tempDir := t.TempDir()
		canonical := filepath.Join(tempDir, settingsFileName)

		migrateLegacySettingsIfNeeded(tempDir, canonical)

		_, err := os.Stat(canonical)
		assert.True(t, os.IsNotExist(err), "no migration when no source files exist")
	})

	t.Run("pre-9.x desktop YAML recovered when no JSON candidates exist", func(t *testing.T) {
		// Redirect the YAML lookup at a tempDir-local file so the test
		// is portable across OSes.
		tempDir := t.TempDir()
		yamlPath := filepath.Join(tempDir, "fake-pre9x-settings.yaml")
		require.NoError(t, os.WriteFile(yamlPath, []byte(`userID: 3580849
deviceID: legacy-device-id
userPro: true
userToken: legacy-token
emailAddress: derek@example.com
`), 0o644))
		legacyYAMLPathFn = func(string) (string, string) { return yamlPath, "desktop" }
		t.Cleanup(func() { legacyYAMLPathFn = func(string) (string, string) { return "", "" } })

		canonical := filepath.Join(tempDir, settingsFileName)
		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		gotStr := string(got)
		assert.Contains(t, gotStr, `"user_id":3580849`)
		assert.Contains(t, gotStr, `"device_id":"legacy-device-id"`)
		assert.Contains(t, gotStr, `"user_level":"pro"`)
		assert.Contains(t, gotStr, `"token":"legacy-token"`)
		assert.Contains(t, gotStr, `"email":"derek@example.com"`)
	})

	t.Run("v9.0.x local.json beats pre-9.x YAML", func(t *testing.T) {
		// Both exist with pro state. local.json is the higher-priority
		// (more recent) source, so it should win.
		tempDir := t.TempDir()
		yamlPath := filepath.Join(tempDir, "fake-pre9x-settings.yaml")
		require.NoError(t, os.WriteFile(yamlPath, []byte(`userID: 1
userPro: true
userToken: legacy-token
`), 0o644))
		legacyYAMLPathFn = func(string) (string, string) { return yamlPath, "desktop" }
		t.Cleanup(func() { legacyYAMLPathFn = func(string) (string, string) { return "", "" } })

		writeLegacy(t, tempDir, []byte(`{"user_id": 2, "user_level": "pro", "token": "v9.0-token"}`))

		canonical := filepath.Join(tempDir, settingsFileName)
		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Contains(t, string(got), `"user_id": 2`,
			"v9.0.x local.json should win over pre-9.x YAML when both have pro")
		assert.Contains(t, string(got), `"v9.0-token"`)
	})

	t.Run("pre-9.x YAML beats v9.1.x bugged nested file", func(t *testing.T) {
		// Pre-9.x has pro; v9.1.x nested has expired (the bugged case).
		// Pre-9.x must win.
		tempDir := t.TempDir()
		yamlPath := filepath.Join(tempDir, "fake-pre9x-settings.yaml")
		require.NoError(t, os.WriteFile(yamlPath, []byte(`userID: 1
userPro: true
userToken: legacy-token
`), 0o644))
		legacyYAMLPathFn = func(string) (string, string) { return yamlPath, "desktop" }
		t.Cleanup(func() { legacyYAMLPathFn = func(string) (string, string) { return "", "" } })

		writeNested(t, tempDir, []byte(`{"user_id": 999, "user_level": "expired"}`))

		canonical := filepath.Join(tempDir, settingsFileName)
		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Contains(t, string(got), `"user_level":"pro"`,
			"pre-9.x YAML with pro should win over v9.1.x nested expired")
		assert.Contains(t, string(got), `"legacy-token"`)
	})

	t.Run("iOS userconfig.yaml recovered when canonical is missing", func(t *testing.T) {
		// On iOS the legacy YAML is sandbox-relative — it lives next to
		// where settings.json now lives, so legacyYAMLCandidate reads
		// from fileDir directly and we can exercise it from a test
		// without monkeypatching $HOME or $APPDATA. (Desktop legacy
		// paths are covered via translateLegacyYAML's unit tests, which
		// don't depend on the OS-specific path resolution.)
		if runtime.GOOS != "ios" {
			t.Skip("iOS-only path: legacy YAML elsewhere is OS-specific")
		}
		tempDir := t.TempDir()
		yamlPath := filepath.Join(tempDir, "userconfig.yaml")
		require.NoError(t, os.WriteFile(yamlPath, []byte(`UserID: 7777
DeviceID: ios-device
Token: tok
`), 0o644))
		canonical := filepath.Join(tempDir, settingsFileName)
		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Contains(t, string(got), `"user_id":7777`)
		assert.Contains(t, string(got), `"device_id":"ios-device"`)
	})

	t.Run("Windows v9.0.x cross-dir local.json recovered when canonical/same-dir/nested all missing", func(t *testing.T) {
		// FD #174606 / engineering#3460: PR #370 moved the Windows daemon
		// from <PUBLIC>\Lantern\data (where v9.0.x Flutter+FFI wrote
		// local.json) to <ProgramData>\Lantern. The same-dir scan can't
		// see across that filesystem boundary, so cross-dir candidates
		// are spliced in by windowsCrossDirCandidatesFn. Verify recovery.
		tempDir := t.TempDir()
		v90xDir := filepath.Join(tempDir, "windows-v90x")
		require.NoError(t, os.MkdirAll(v90xDir, 0o755))
		want := []byte(`{"user_id": 195646669, "user_level": "pro", "token": "preserved"}`)
		require.NoError(t, os.WriteFile(filepath.Join(v90xDir, legacySettingsFileName), want, 0o644))

		windowsCrossDirCandidatesFn = func(string) []candidateSource {
			return readWindowsCrossDirCandidates(v90xDir)
		}
		t.Cleanup(func() {
			windowsCrossDirCandidatesFn = func(string) []candidateSource { return nil }
		})

		canonical := filepath.Join(tempDir, settingsFileName)
		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, want, got, "v9.0.x cross-dir local.json must be migrated to canonical")
	})

	t.Run("Windows v9.0.x cross-dir falls back to settings.json when local.json missing", func(t *testing.T) {
		// Defensive case: a user whose v9.0.x file got renamed by an
		// earlier partial upgrade attempt. The cross-dir scan should
		// still pick up settings.json under ${PUBLIC}\Lantern\data.
		tempDir := t.TempDir()
		v90xDir := filepath.Join(tempDir, "windows-v90x")
		require.NoError(t, os.MkdirAll(v90xDir, 0o755))
		want := []byte(`{"user_id": 42, "user_level": "pro"}`)
		require.NoError(t, os.WriteFile(filepath.Join(v90xDir, settingsFileName), want, 0o644))

		windowsCrossDirCandidatesFn = func(string) []candidateSource {
			return readWindowsCrossDirCandidates(v90xDir)
		}
		t.Cleanup(func() {
			windowsCrossDirCandidatesFn = func(string) []candidateSource { return nil }
		})

		canonical := filepath.Join(tempDir, settingsFileName)
		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, want, got, "v9.0.x cross-dir settings.json must be migrated when local.json absent")
	})

	t.Run("Windows v9.0.x cross-dir loses to same-dir v9.0.x local.json", func(t *testing.T) {
		// If both exist, same-dir wins — it's strictly more recent state.
		// (Cross-dir is only a thing because Windows users skipped through
		// the v9.0.x → v9.1.x transition; same-dir local.json means the
		// daemon already migrated once and the cross-dir copy is stale.)
		tempDir := t.TempDir()
		v90xDir := filepath.Join(tempDir, "windows-v90x")
		require.NoError(t, os.MkdirAll(v90xDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(v90xDir, legacySettingsFileName),
			[]byte(`{"user_id": 999, "user_level": "pro"}`), 0o644))
		sameDirPro := []byte(`{"user_id": 1, "user_level": "pro", "token": "same-dir"}`)
		require.NoError(t, os.WriteFile(filepath.Join(tempDir, legacySettingsFileName), sameDirPro, 0o644))

		windowsCrossDirCandidatesFn = func(string) []candidateSource {
			return readWindowsCrossDirCandidates(v90xDir)
		}
		t.Cleanup(func() {
			windowsCrossDirCandidatesFn = func(string) []candidateSource { return nil }
		})

		canonical := filepath.Join(tempDir, settingsFileName)
		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, sameDirPro, got, "same-dir v9.0.x must outrank cross-dir v9.0.x")
	})

	t.Run("Windows v9.0.x cross-dir-pro beats v9.1.x nested-expired", func(t *testing.T) {
		// The headline case: user upgrades from v9.0.x Windows (Pro state
		// at ${PUBLIC}\Lantern\data\local.json) through a buggy v9.1.x
		// build (which wrote an expired record at <ProgramData>\Lantern\data\settings.json)
		// to the fix. The cross-dir Pro must win over the nested expired.
		tempDir := t.TempDir()
		v90xDir := filepath.Join(tempDir, "windows-v90x")
		require.NoError(t, os.MkdirAll(v90xDir, 0o755))
		crossDirPro := []byte(`{"user_id": 195646669, "user_level": "pro"}`)
		require.NoError(t, os.WriteFile(filepath.Join(v90xDir, legacySettingsFileName), crossDirPro, 0o644))
		writeNested(t, tempDir, []byte(`{"user_id": 99, "user_level": "expired"}`))

		windowsCrossDirCandidatesFn = func(string) []candidateSource {
			return readWindowsCrossDirCandidates(v90xDir)
		}
		t.Cleanup(func() {
			windowsCrossDirCandidatesFn = func(string) []candidateSource { return nil }
		})

		canonical := filepath.Join(tempDir, settingsFileName)
		migrateLegacySettingsIfNeeded(tempDir, canonical)

		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, crossDirPro, got, "cross-dir pro must beat nested expired (engineering#3460)")
	})

	t.Run("unreadable canonical (non-ENOENT) skips migration", func(t *testing.T) {
		// Permission error on the canonical path: don't fall through and
		// overwrite a file we couldn't read. unix only — windows handles
		// permissions differently and chmod wouldn't reproduce this.
		if runtime.GOOS == "windows" {
			t.Skip("permission semantics differ on windows")
		}
		tempDir := t.TempDir()
		canonical := filepath.Join(tempDir, settingsFileName)
		require.NoError(t, os.WriteFile(canonical, []byte(`{"user_level": "expired"}`), 0o644))
		// Make the file unreadable.
		require.NoError(t, os.Chmod(canonical, 0o000))
		t.Cleanup(func() { _ = os.Chmod(canonical, 0o644) })
		// Stage a legacy-pro candidate that would otherwise win.
		writeLegacy(t, tempDir, []byte(`{"user_id": 1, "user_level": "pro"}`))

		migrateLegacySettingsIfNeeded(tempDir, canonical)

		// Restore readability and confirm the canonical contents are
		// unchanged (still the expired body, not the legacy-pro body).
		require.NoError(t, os.Chmod(canonical, 0o644))
		got, err := os.ReadFile(canonical)
		require.NoError(t, err)
		assert.Equal(t, `{"user_level": "expired"}`, string(got),
			"canonical with non-ENOENT read error should be left alone")
	})
}

func TestReload(t *testing.T) {
	initSettingsAt := func(t *testing.T, contents string) string {
		t.Helper()
		Reset()
		t.Cleanup(Reset)
		dir := t.TempDir()
		path := filepath.Join(dir, settingsFileName)
		require.NoError(t, os.WriteFile(path, []byte(contents), 0644))
		require.NoError(t, InitSettings(dir))
		return path
	}

	t.Run("adopts values written by another process", func(t *testing.T) {
		path := initSettingsAt(t, `{"country_code": "US", "device_id": "old-device"}`)
		require.Equal(t, "US", GetString(CountryCodeKey))

		require.NoError(t, os.WriteFile(path, []byte(`{"country_code": "IR", "device_id": "new-device"}`), 0644))
		require.Equal(t, "US", GetString(CountryCodeKey), "cached value is served until a reload")

		require.NoError(t, Reload())
		assert.Equal(t, "IR", GetString(CountryCodeKey))
		assert.Equal(t, "new-device", GetString(DeviceIDKey))
	})

	t.Run("keeps this process's own writes", func(t *testing.T) {
		initSettingsAt(t, `{"country_code": "US"}`)
		require.NoError(t, Set(DeviceIDKey, "written-here"))

		require.NoError(t, Reload())
		assert.Equal(t, "written-here", GetString(DeviceIDKey), "Set persists before returning, so a reload reads it back")
	})

	t.Run("leaves settings intact when the file is unreadable", func(t *testing.T) {
		path := initSettingsAt(t, `{"country_code": "US"}`)
		require.NoError(t, os.WriteFile(path, []byte(`{invalid json}`), 0644))

		assert.Error(t, Reload())
		assert.Equal(t, "US", GetString(CountryCodeKey), "a failed reload must not wipe live settings")
	})

	t.Run("adopts deletions", func(t *testing.T) {
		path := initSettingsAt(t, `{"country_code": "US", "user_id": "user-1"}`)
		require.Equal(t, "user-1", GetString(UserIDKey))

		require.NoError(t, os.WriteFile(path, []byte(`{"country_code": "IR"}`), 0644))
		require.NoError(t, Reload())

		assert.Equal(t, "IR", GetString(CountryCodeKey), "changed values are adopted")
		assert.Empty(t, GetString(UserIDKey), "a removed key is dropped, not kept")
		assert.False(t, Exists(UserIDKey))
	})

	t.Run("missing file is not an error", func(t *testing.T) {
		path := initSettingsAt(t, `{"country_code": "US"}`)
		require.NoError(t, os.Remove(path))

		assert.NoError(t, Reload())
		assert.Equal(t, "US", GetString(CountryCodeKey))
	})

	t.Run("errors when uninitialized", func(t *testing.T) {
		Reset()
		t.Cleanup(Reset)
		assert.Error(t, Reload())
	})
}

func TestReloadRacesNothing(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	dir := t.TempDir()
	path := filepath.Join(dir, settingsFileName)
	require.NoError(t, os.WriteFile(path, []byte(`{"country_code": "US"}`), 0644))
	require.NoError(t, InitSettings(dir))

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = GetString(CountryCodeKey)
					_ = GetBool(SplitTunnelKey)
				}
			}
		}()
	}
	for range 50 {
		require.NoError(t, Reload())
	}
	close(stop)
	wg.Wait()
}

func TestWriteAdoptsOtherProcessState(t *testing.T) {
	initAt := func(t *testing.T, contents string) string {
		t.Helper()
		Reset()
		t.Cleanup(Reset)
		dir := t.TempDir()
		path := filepath.Join(dir, settingsFileName)
		require.NoError(t, os.WriteFile(path, []byte(contents), 0644))
		require.NoError(t, InitSettings(dir))
		return path
	}

	t.Run("keeps keys another process persisted", func(t *testing.T) {
		path := initAt(t, `{"locale": "en-US"}`)
		require.NoError(t, os.WriteFile(path, []byte(`{"locale": "en-US", "token": "fresh"}`), 0644))

		require.NoError(t, Set(TimeZoneKey, "UTC"))

		assert.Equal(t, "fresh", GetString(TokenKey), "another process's write must survive this write")
		assert.Equal(t, "UTC", GetString(TimeZoneKey))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		var onDisk map[string]any
		require.NoError(t, json.Unmarshal(got, &onDisk))
		assert.Equal(t, "fresh", onDisk["token"])
		assert.Equal(t, "UTC", onDisk["time_zone"])
	})

	t.Run("adopts deletions by another process", func(t *testing.T) {
		path := initAt(t, `{"locale": "en-US", "token": "old"}`)
		require.NoError(t, os.WriteFile(path, []byte(`{"locale": "en-US"}`), 0644))

		require.NoError(t, Set(TimeZoneKey, "UTC"))

		assert.False(t, Exists(TokenKey), "a key another process deleted must stay deleted")
		assert.Equal(t, "free", GetString(UserLevelKey), "defaults reapply when the file omits them")
	})

	t.Run("recreates a missing file from the current snapshot", func(t *testing.T) {
		path := initAt(t, `{"locale": "en-US"}`)
		require.NoError(t, os.Remove(path))

		require.NoError(t, Set(TimeZoneKey, "UTC"))

		assert.Equal(t, "en-US", GetString(LocaleKey))
		assert.FileExists(t, path)
	})

	t.Run("replaces a corrupt file with valid state", func(t *testing.T) {
		path := initAt(t, `{"locale": "en-US"}`)
		require.NoError(t, os.WriteFile(path, []byte(`{nope`), 0644))

		require.NoError(t, Set(TimeZoneKey, "UTC"))

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.True(t, validSettingsJSON(got), "the corrupt file must be overwritten with valid JSON")
		assert.Equal(t, "en-US", GetString(LocaleKey))
	})

	t.Run("patch keeps unrelated cross-process writes", func(t *testing.T) {
		path := initAt(t, `{"locale": "en-US"}`)
		require.NoError(t, os.WriteFile(path, []byte(`{"locale": "en-US", "user_level": "pro"}`), 0644))

		require.NoError(t, Patch(Settings{CountryCodeKey: "IR", TimeZoneKey: "Asia/Tehran"}))

		assert.Equal(t, "pro", GetString(UserLevelKey), "another process's write must survive a patch")
		assert.Equal(t, "IR", GetString(CountryCodeKey))
	})
}

func TestFailedSaveIsNotRevertedByLaterWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a read-only directory to force save failures")
	}
	Reset()
	t.Cleanup(Reset)
	dir := t.TempDir()
	require.NoError(t, InitSettings(dir))
	require.NoError(t, Set(TokenKey, "live-token"))

	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	require.Error(t, Clear(TokenKey), "save must fail in a read-only directory")
	assert.False(t, Exists(TokenKey), "the deletion is visible in this process despite the failed save")

	require.NoError(t, os.Chmod(dir, 0o755))
	require.NoError(t, Set(LocaleKey, "fa-IR"))

	assert.False(t, Exists(TokenKey), "a later write must not resurrect the cleared token")
	got, err := os.ReadFile(filepath.Join(dir, settingsFileName))
	require.NoError(t, err)
	var onDisk map[string]any
	require.NoError(t, json.Unmarshal(got, &onDisk))
	_, tokenOnDisk := onDisk["token"]
	assert.False(t, tokenOnDisk, "the pending deletion must reach the file with the next save")
	assert.Equal(t, "fa-IR", onDisk["locale"])
}

func TestStructValuesSurviveUnrelatedWrites(t *testing.T) {
	type location struct {
		CountryCode string `json:"country_code,omitempty"`
	}
	type server struct {
		Tag      string   `json:"tag"`
		Location location `json:"location,omitempty"`
	}
	Reset()
	t.Cleanup(Reset)
	require.NoError(t, InitSettings(t.TempDir()))
	require.NoError(t, Set(SelectedServerKey, server{Tag: "manual", Location: location{CountryCode: "IR"}}))

	var immediate server
	require.NoError(t, GetStruct(SelectedServerKey, &immediate))
	assert.Equal(t, "IR", immediate.Location.CountryCode)

	require.NoError(t, Set(LocaleKey, "en-US"))

	var afterWrite server
	require.NoError(t, GetStruct(SelectedServerKey, &afterWrite))
	assert.Equal(t, "manual", afterWrite.Tag)
	assert.Equal(t, "IR", afterWrite.Location.CountryCode,
		"JSON-tagged fields must survive the disk round-trip an unrelated write performs")
}

func TestConditionalWritesDecideAgainstFile(t *testing.T) {
	initAt := func(t *testing.T, contents string) string {
		t.Helper()
		Reset()
		t.Cleanup(Reset)
		dir := t.TempDir()
		path := filepath.Join(dir, settingsFileName)
		require.NoError(t, os.WriteFile(path, []byte(contents), 0644))
		require.NoError(t, InitSettings(dir))
		return path
	}

	t.Run("ReplaceString spares a newer value another process wrote", func(t *testing.T) {
		path := initAt(t, `{}`)
		require.NoError(t, Set(LogLevelKey, "trace"))
		require.NoError(t, os.WriteFile(path, []byte(`{"log_level": "debug"}`), 0644))

		require.NoError(t, ReplaceString(LogLevelKey, "trace", "info"))

		assert.Equal(t, "debug", GetString(LogLevelKey),
			"a deliberate level persisted by another process must survive the demotion")
	})

	t.Run("ReplaceString replaces a matching value", func(t *testing.T) {
		initAt(t, `{"log_level": "trace"}`)
		require.NoError(t, ReplaceString(LogLevelKey, "trace", "info"))
		assert.Equal(t, "info", GetString(LogLevelKey))
	})

	t.Run("SetIfAbsent spares a value another process wrote", func(t *testing.T) {
		path := initAt(t, `{}`)
		require.NoError(t, os.WriteFile(path, []byte(`{"log_level": "warn"}`), 0644))

		require.NoError(t, SetIfAbsent(LogLevelKey, "info"))

		assert.Equal(t, "warn", GetString(LogLevelKey))
	})

	t.Run("SetIfAbsent seeds a missing value", func(t *testing.T) {
		initAt(t, `{}`)
		require.NoError(t, SetIfAbsent(LogLevelKey, "info"))
		assert.Equal(t, "info", GetString(LogLevelKey))
	})
}

func TestUnreadableFileStillAppliesWritesLocally(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses file permissions to force read failures")
	}
	Reset()
	t.Cleanup(Reset)
	dir := t.TempDir()
	path := filepath.Join(dir, settingsFileName)
	require.NoError(t, InitSettings(dir))
	require.NoError(t, Set(TokenKey, "live-token"))

	require.NoError(t, os.Chmod(path, 0o000))
	t.Cleanup(func() { os.Chmod(path, 0o644) })
	require.Error(t, Clear(TokenKey), "an unreadable file must surface as an error")
	assert.False(t, Exists(TokenKey), "logout must still take effect in this process")
	require.NoError(t, os.Chmod(path, 0o000)) // confirm the failed write left the file alone
	got, err := os.ReadFile(path)
	require.Error(t, err, "the unreadable file must not be overwritten")
	_ = got

	require.NoError(t, os.Chmod(path, 0o644))
	require.NoError(t, Set(LocaleKey, "en-US"))

	assert.False(t, Exists(TokenKey))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var onDisk map[string]any
	require.NoError(t, json.Unmarshal(raw, &onDisk))
	_, tokenOnDisk := onDisk["token"]
	assert.False(t, tokenOnDisk, "the journaled tombstone must reach the file once it is writable")
}

func TestInitSettingsSkipsMigrationDespiteMalformedTestingEnv(t *testing.T) {
	t.Setenv(env.Testing.String(), "yes")
	Reset()
	t.Cleanup(Reset)
	dir := t.TempDir()
	legacy := []byte(`{"user_level":"pro","token":"leaked"}`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, legacySettingsFileName), legacy, 0o644))

	require.NoError(t, InitSettings(dir))

	assert.NotEqual(t, "pro", GetString(UserLevelKey),
		"a malformed RADIANCE_TESTING value must not re-enable the migration in a test binary")
	assert.False(t, Exists(TokenKey))
}
