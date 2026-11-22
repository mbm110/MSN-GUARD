package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/goccy/go-yaml"
)

// legacyYAMLPathFn is overridable so tests can redirect lookup to a temp
// dir without touching the host's app-config layout.
var legacyYAMLPathFn = legacyYAMLPath

// legacyYAMLCandidate returns the pre-9.x flashlight/lantern-client
// settings file (if any), translated into canonical JSON. Android is
// excluded — it persisted state in an encrypted SQLite that needs a
// Kotlin-side migration.
func legacyYAMLCandidate(fileDir string) candidateSource {
	path, layout := legacyYAMLPathFn(fileDir)
	if path == "" {
		return candidateSource{}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("pre-9.x yaml read failed", "path", path, "error", err)
		}
		return candidateSource{}
	}
	translated, err := translateLegacyYAML(raw, layout)
	if err != nil {
		slog.Warn("pre-9.x yaml translate failed", "path", path, "error", err)
		return candidateSource{}
	}
	return candidateSource{
		path:     path,
		contents: translated,
		exists:   true,
		label:    fmt.Sprintf("pre-9.x %s yaml", layout),
	}
}

func legacyYAMLPath(fileDir string) (path, layout string) {
	switch runtime.GOOS {
	case "darwin", "windows":
		if cfg, err := os.UserConfigDir(); err == nil {
			return filepath.Join(cfg, "Lantern", "settings.yaml"), "desktop"
		}
	case "linux":
		// Pre-9.x appdir lowercased the app name on linux only.
		if cfg, err := os.UserConfigDir(); err == nil {
			return filepath.Join(cfg, "lantern", "settings.yaml"), "desktop"
		}
	case "ios":
		// iOS lantern-client wrote userconfig.yaml inside the app sandbox,
		// the same sandbox radiance's dataDir lives in.
		return filepath.Join(fileDir, "userconfig.yaml"), "ios"
	}
	return "", ""
}

func translateLegacyYAML(raw []byte, layout string) ([]byte, error) {
	type canonical struct {
		UserID    int64  `json:"user_id,omitempty"`
		DeviceID  string `json:"device_id,omitempty"`
		UserLevel string `json:"user_level,omitempty"`
		Token     string `json:"token,omitempty"`
		Email     string `json:"email,omitempty"`
	}

	var out canonical
	switch layout {
	case "desktop":
		var d struct {
			UserID       int64  `yaml:"userID"`
			DeviceID     string `yaml:"deviceID"`
			UserPro      bool   `yaml:"userPro"`
			UserToken    string `yaml:"userToken"`
			EmailAddress string `yaml:"emailAddress"`
		}
		if err := yaml.Unmarshal(raw, &d); err != nil {
			return nil, fmt.Errorf("desktop yaml: %w", err)
		}
		out.UserID = d.UserID
		out.DeviceID = d.DeviceID
		out.Token = d.UserToken
		out.Email = d.EmailAddress
		switch {
		case d.UserPro:
			out.UserLevel = "pro"
		case d.UserID != 0:
			// Identified-but-not-pro → "free" so downstream sees a real value.
			out.UserLevel = "free"
		}
	case "ios":
		var i struct {
			UserID   int64  `yaml:"UserID"`
			DeviceID string `yaml:"DeviceID"`
			Token    string `yaml:"Token"`
		}
		if err := yaml.Unmarshal(raw, &i); err != nil {
			return nil, fmt.Errorf("ios yaml: %w", err)
		}
		out.UserID = i.UserID
		out.DeviceID = i.DeviceID
		out.Token = i.Token
		// user_level left empty: iOS didn't persist it here, so the next
		// /account/login is authoritative.
	default:
		return nil, fmt.Errorf("unknown layout: %s", layout)
	}
	return json.Marshal(out)
}
