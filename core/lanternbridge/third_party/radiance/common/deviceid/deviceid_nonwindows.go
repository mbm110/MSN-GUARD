//go:build !windows
// +build !windows

package deviceid

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/common/fileperm"
)

// Get returns a unique identifier for this device. The identifier is a random UUID that's stored on
// disk at {path}/.lanternsecrets/.deviceid. If unable to read/write to that location, this defaults to the
// old-style device ID derived from MAC address.
func Get(path string) string {
	path = filepath.Join(path, ".lanternsecrets")
	err := os.Mkdir(path, 0o755)
	if err != nil && !os.IsExist(err) {
		slog.Error("Unable to create folder to store deviceID, defaulting to old-style device ID", "error", err)
		return OldStyleDeviceID()
	}

	filename := filepath.Join(path, ".deviceid")
	existing, err := atomicfile.ReadFile(filename)
	if err == nil {
		return string(existing)
	}

	if migrated, ok := migrateLegacyDeviceID(filename); ok {
		return migrated
	}

	slog.Debug("Storing new deviceID")
	_deviceID, err := uuid.NewRandom()
	if err != nil {
		slog.Error("Error generating new deviceID, defaulting to old-style device ID", "error", err)
		return OldStyleDeviceID()
	}
	deviceID := _deviceID.String()
	if err := atomicfile.WriteFile(filename, []byte(deviceID), fileperm.File); err != nil {
		slog.Error("Error storing new deviceID, defaulting to old-style device ID", "error", err)
		return OldStyleDeviceID()
	}
	return deviceID
}

// migrateLegacyDeviceID copies a device ID from the pre-refactor location ($HOME/.lanternsecrets/.deviceid)
// to dst, returning the migrated ID on success. The legacy file is left in place.
// TODO: remove once clients predating the $HOME/.lanternsecrets location are no
// longer in the field; kept so upgrades from those builds don't regenerate the device ID.
func migrateLegacyDeviceID(dst string) (string, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	legacy := filepath.Join(home, ".lanternsecrets", ".deviceid")
	contents, err := atomicfile.ReadFile(legacy)
	if err != nil {
		return "", false
	}
	if err := atomicfile.WriteFile(dst, contents, fileperm.File); err != nil {
		slog.Warn("Failed to migrate legacy deviceID", "error", err)
		return "", false
	}
	slog.Info("Migrated legacy deviceID", "from", legacy, "to", dst)
	return string(contents), true
}
