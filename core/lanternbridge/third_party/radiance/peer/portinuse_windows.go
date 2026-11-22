package peer

import (
	"errors"
	"syscall"
)

// portInUse reports whether err is a listen failing because another socket
// holds the port, or because Windows has reserved it.
func portInUse(err error) bool {
	const (
		wsaeacces     syscall.Errno = 10013
		wsaeaddrinuse syscall.Errno = 10048
	)
	return errors.Is(err, wsaeaddrinuse) || errors.Is(err, wsaeacces)
}
