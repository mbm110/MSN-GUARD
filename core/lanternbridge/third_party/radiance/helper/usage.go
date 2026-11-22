package helper

import (
	"sort"
	"sync"
)

// PairedBytes is the bytes relayed for one helper pairing in a usage report.
// PairingID identifies a friend relationship and must never be logged.
type PairedBytes struct {
	PairingID string `json:"pairing_id"`
	Bytes     uint64 `json:"bytes"`
}

// Usage accumulates bytes relayed per helper pairing until a report takes
// them. It is in memory only, so a restart loses what was not yet reported.
// The zero value is ready to use, methods on a nil Usage do nothing, and it is
// safe for concurrent use.
type Usage struct {
	mu      sync.Mutex
	pending map[string]uint64
	flush   func()
}

// Add counts n bytes relayed for pairing. An empty pairing or a zero n is
// ignored.
func (u *Usage) Add(pairing string, n uint64) {
	if u == nil || pairing == "" || n == 0 {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.pending == nil {
		u.pending = make(map[string]uint64)
	}
	u.pending[pairing] += n
}

// SetFlush sets f to run at the start of every Take, without u's lock held,
// so a source that batches bytes can Add them first.
func (u *Usage) SetFlush(f func()) {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.flush = f
}

// Take returns the bytes added since the last Take, sorted by pairing, and
// forgets them; nil when there are none.
func (u *Usage) Take() []PairedBytes {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	flush := u.flush
	u.mu.Unlock()
	if flush != nil {
		flush()
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.pending) == 0 {
		return nil
	}
	out := make([]PairedBytes, 0, len(u.pending))
	for id, n := range u.pending {
		out = append(out, PairedBytes{PairingID: id, Bytes: n})
	}
	clear(u.pending)
	sort.Slice(out, func(i, j int) bool { return out[i].PairingID < out[j].PairingID })
	return out
}

// Restore adds back what a Take returned, for a report that was not
// delivered.
func (u *Usage) Restore(ps []PairedBytes) {
	for _, p := range ps {
		u.Add(p.PairingID, p.Bytes)
	}
}
