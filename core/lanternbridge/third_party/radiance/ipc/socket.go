//go:build !android && !ios && !windows

package ipc

import (
	"os"
)

// use a var so it can be overridden in tests
var _socketPath = "/var/run/lantern/lanternd.sock"

func setSocketPathForTesting(path string) {
	_socketPath = path
}

func socketPath() string {
	return _socketPath
}

func setPermissions() error {
	// we set the socket as world accessible and authorize users on connect
	// by checking if they're a sudoer instead.
	return os.Chmod(socketPath(), 0666)
}
