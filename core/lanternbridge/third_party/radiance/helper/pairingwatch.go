package helper

import (
	"context"
	"sync"
)

// PairingWatch cancels a client's in-flight lantern-cloud call when its
// pairings change, so a revocation never waits on that call. Its zero value
// is ready to use, and it is safe for concurrent use. It serves one call at a
// time.
type PairingWatch struct {
	mu     sync.Mutex
	gen    uint64
	cancel context.CancelFunc
}

// Changed cancels the call in flight, if any, and any call whose snapshot
// predates it.
func (w *PairingWatch) Changed() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gen++
	if w.cancel != nil {
		w.cancel()
	}
}

// Snapshot returns a token for Watch, taken before the pairings are read.
func (w *PairingWatch) Snapshot() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.gen
}

// Watch returns ctx for one call, cancelled by a Changed since snapshot, and
// a release the caller must call when the call ends.
func (w *PairingWatch) Watch(ctx context.Context, snapshot uint64) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.gen != snapshot {
		cancel()
	} else {
		w.cancel = cancel
	}
	return ctx, func() {
		w.mu.Lock()
		w.cancel = nil
		w.mu.Unlock()
		cancel()
	}
}
