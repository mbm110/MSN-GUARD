//go:build android || ios

package ipc

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/log"
)

// setSocketPathForTesting does nothing on mobile: the socket path is derived
// from settings at runtime, so there is nothing to override.
func setSocketPathForTesting(path string) {}

func socketPath() string {
	return settings.GetString(settings.DataPathKey) + "/lantern.sock"
}

func setPermissions() error {
	// chown to shared directory owner:group since /var/run/ is only writable by system
	path := socketPath()
	uid, gid := getNonRootOwner(path)
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	if err := os.Chmod(path, 0660); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

func getNonRootOwner(path string) (uid, gid int) {
	uid = os.Getuid()
	gid = os.Getgid()
	if uid != 0 {
		return uid, gid
	}

	slog.Log(context.Background(), log.LevelTrace, "searching for non-root owner of", "path", path)
	for {
		parentDir := filepath.Dir(path)
		if parentDir == path || parentDir == "/" {
			break
		}
		path = parentDir

		fInfo, err := os.Stat(path)
		if err != nil {
			slog.Log(context.Background(), log.LevelTrace, "stat error", "path", path, "error", err)
			continue
		}
		stat, ok := fInfo.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if int(stat.Uid) != 0 {
			slog.Log(context.Background(), log.LevelTrace, "found non-root owner", "path", path, "uid", stat.Uid, "gid", stat.Gid)
			return int(stat.Uid), int(stat.Gid)
		}
	}
	if slog.Default().Enabled(context.Background(), log.LevelTrace) {
		slog.Warn("falling back to root owner for", "path", path)
	}
	return uid, gid
}
