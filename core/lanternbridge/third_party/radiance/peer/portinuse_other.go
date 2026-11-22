//go:build !windows

package peer

import (
	"errors"
	"syscall"
)

// portInUse reports whether err is a listen failing because another socket
// holds the port.
func portInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
