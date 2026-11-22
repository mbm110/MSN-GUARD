package testutil

import (
	"net"
	"time"
)

// bypassLockAddr is a loopback port held as a cross-process mutex: only one process can bind
// it, on every OS, and it's freed when the holder exits, even by crashing.
const bypassLockAddr = "127.0.0.1:14984"

// LockBypassPort serializes tests that bind or depend on the fixed bypass proxy
// port. Packages run their tests in parallel processes, so without it one
// package's proxy can appear in the middle of another's test.
func LockBypassPort() (unlock func()) {
	for {
		l, err := net.Listen("tcp", bypassLockAddr)
		if err == nil {
			return func() { l.Close() }
		}
		time.Sleep(50 * time.Millisecond)
	}
}
