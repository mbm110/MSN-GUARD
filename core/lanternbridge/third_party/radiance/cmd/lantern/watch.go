package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/getlantern/radiance/ipc"
)

const (
	defaultReconnectTimeout = 60 * time.Second
	reconnectInitialBackoff = 500 * time.Millisecond
	reconnectMaxBackoff     = 5 * time.Second

	reconnectPrefix = "Daemon disconnected; retrying"
	spinnerFrames   = `|/-\`
	spinnerInterval = 150 * time.Millisecond
)

type reconnectState struct {
	timeout  time.Duration
	deadline time.Time
	backoff  time.Duration
	notified bool
	spinIdx  int
}

func newReconnect(timeout time.Duration) *reconnectState {
	return &reconnectState{timeout: timeout}
}

func (r *reconnectState) onError() time.Duration {
	if r.timeout <= 0 {
		return 0
	}
	now := time.Now()
	if r.deadline.IsZero() {
		r.deadline = now.Add(r.timeout)
		r.backoff = reconnectInitialBackoff
	}
	if now.After(r.deadline) {
		return 0
	}
	wait := r.backoff
	r.backoff *= 2
	r.backoff = min(r.backoff, reconnectMaxBackoff)
	return wait
}

func (r *reconnectState) onSuccess() {
	if r.notified {
		clearReconnectLine()
		fmt.Fprint(os.Stderr, "Daemon reconnected.\r\n")
		r.notified = false
	}
	r.deadline = time.Time{}
	r.backoff = 0
}

func (r *reconnectState) waitForRetry(ctx context.Context, wait time.Duration) error {
	if wait <= 0 {
		return nil
	}
	if !stderrIsTTY() {
		if !r.notified {
			fmt.Fprintln(os.Stderr, reconnectPrefix+"...")
			r.notified = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
			return nil
		}
	}
	deadline := time.Now().Add(wait)
	for {
		c := spinnerFrames[r.spinIdx%len(spinnerFrames)]
		r.spinIdx++
		fmt.Fprintf(os.Stderr, "\r%s %c ", reconnectPrefix, c)
		r.notified = true
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil
		}
		sleep := min(remaining, spinnerInterval)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
	}
}

func (r *reconnectState) abandon() {
	if r.notified {
		clearReconnectLine()
		r.notified = false
	}
}

func stderrIsTTY() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

func stdoutIsTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func clearReconnectLine() {
	if stderrIsTTY() {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
}

func callWithReconnect(ctx context.Context, st *reconnectState, fn func() error) error {
	for {
		err := fn()
		if err == nil {
			st.onSuccess()
			return nil
		}
		if !errors.Is(err, ipc.ErrIPCNotRunning) {
			st.abandon()
			return err
		}
		wait := st.onError()
		if wait <= 0 {
			st.abandon()
			return fmt.Errorf("daemon unreachable: %w", err)
		}
		if err := st.waitForRetry(ctx, wait); err != nil {
			st.abandon()
			return err
		}
	}
}
