package main

import (
	"context"
	"os"

	"golang.org/x/term"
)

// quitOnKey cancels ctx when q, Q, or Ctrl-C is read from stdin.
// The returned cleanup MUST be deferred: on a TTY it restores terminal
// state from raw mode. Raw mode also disables \n -> \r\n translation, so
// callers must emit \r\n explicitly to avoid stairstepping.
func quitOnKey(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return ctx, cancel
	}
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return ctx, cancel
	}
	go watchKeys(os.Stdin, cancel)
	return ctx, func() {
		_ = term.Restore(fd, oldState)
		cancel()
	}
}

func watchKeys(r *os.File, cancel context.CancelFunc) {
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if err != nil || n == 0 {
			return
		}
		switch buf[0] {
		case 'q', 'Q', 0x03:
			cancel()
			return
		}
	}
}
