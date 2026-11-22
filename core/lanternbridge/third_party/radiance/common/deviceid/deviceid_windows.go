//go:build windows
// +build windows

package deviceid

import (
	"log/slog"

	"github.com/google/uuid"
	"golang.org/x/sys/windows/registry"
)

const (
	keyPath = `Software\Lantern`
)

// Get returns a unique identifier for this device. The identifier is a random UUID that's stored in the registry
// at HKEY_CURRENT_USERS\Software\Lantern\deviceid. If unable to read/write to the registry, this defaults to the
// old-style device ID derived from MAC address.
func Get(_ string) string {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE|registry.SET_VALUE|registry.WRITE)
	if err != nil {
		slog.Error("Unable to create registry entry to store deviceID, defaulting to old-style device ID", "error", err)
		return OldStyleDeviceID()
	}
	defer key.Close()

	existing, _, err := key.GetStringValue("deviceid")
	if err != nil {
		if err != registry.ErrNotExist {
			slog.Error("Unexpected error reading deviceID, default to old-style device ID:", "error", err)
			return OldStyleDeviceID()
		}
		slog.Debug("Storing new deviceID")
		_deviceID, err := uuid.NewRandom()
		if err != nil {
			slog.Error("Error generating new deviceID, defaulting to old-style device ID:", "error", err)
			return OldStyleDeviceID()
		}
		deviceID := _deviceID.String()
		err = key.SetStringValue("deviceid", deviceID)
		if err != nil {
			slog.Error("Error storing new deviceID, defaulting to old-style device ID", "error", err)
			return OldStyleDeviceID()
		}
		return deviceID
	}

	return existing
}
