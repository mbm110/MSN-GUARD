package settings

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// windowsCrossDirCandidatesFn is overridable so tests can redirect the
// lookup to a temp dir without touching the host's %PUBLIC%.
var windowsCrossDirCandidatesFn = windowsCrossDirCandidates

// windowsCrossDirCandidates returns settings candidates from the v9.0.x
// Windows data directory (${PUBLIC}\Lantern\data), which the same-dir
// migration doesn't cover: radiance's data dir moved to
// ${ProgramData}\Lantern and the two directories don't share a parent, so
// the same-dir candidates never see the v9.0.x file.
//
// Returns nil on non-Windows hosts or when %PUBLIC% is unset.
func windowsCrossDirCandidates(fileDir string) []candidateSource {
	if runtime.GOOS != "windows" {
		return nil
	}
	pub := os.Getenv("PUBLIC")
	if pub == "" {
		return nil
	}
	v90xDir := filepath.Join(pub, "Lantern", "data")
	// If the caller's fileDir already IS the v9.0.x dir (e.g. someone
	// manually pointed lanternd at ${PUBLIC}\Lantern\data), the same-dir
	// candidates already cover it — no need to also list it here.
	// NTFS is case-insensitive by default, so a caller that supplies an
	// equivalent path with different casing or separators should also
	// hit this guard.
	if samePathWindows(fileDir, v90xDir) {
		return nil
	}
	return readWindowsCrossDirCandidates(v90xDir)
}

// samePathWindows reports whether two paths refer to the same directory
// on Windows. Cleans both sides (collapsing `.` / `..` and normalizing
// separators) and compares case-insensitively because NTFS is
// case-insensitive by default. Not a substitute for filepath.EvalSymlinks
// or device-id comparison — it only handles the common "user passed the
// same dir written differently" case, which is the only one the
// duplicate-scan guard needs to defend against.
func samePathWindows(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// readWindowsCrossDirCandidates is split out so tests can drive the path
// resolution directly without needing to spoof %PUBLIC% / GOOS.
func readWindowsCrossDirCandidates(v90xDir string) []candidateSource {
	// legacySettingsFileName is tried first because it's the actual
	// v9.0.x name; settingsFileName is included as a defensive
	// fallback for users whose v9.0.x file got renamed by a partial /
	// failed earlier upgrade attempt.
	specs := []struct {
		name, label string
	}{
		{legacySettingsFileName, fmt.Sprintf("v9.0.x Windows %s", filepath.Join(v90xDir, legacySettingsFileName))},
		{settingsFileName, fmt.Sprintf("v9.0.x Windows %s", filepath.Join(v90xDir, settingsFileName))},
	}
	var out []candidateSource
	for _, s := range specs {
		full := filepath.Join(v90xDir, s.name)
		b, err := os.ReadFile(full)
		switch {
		case err == nil:
			out = append(out, candidateSource{
				path:     full,
				contents: b,
				exists:   true,
				label:    s.label,
			})
		case errors.Is(err, fs.ErrNotExist):
			// Expected — fresh install or that filename never existed for this user.
		default:
			slog.Warn("v9.0.x Windows cross-dir read failed",
				"path", full, "error", err)
		}
	}
	return out
}
