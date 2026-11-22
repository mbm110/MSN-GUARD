package vpn

import (
	"math/bits"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/env"

	"github.com/sagernet/sing/common/buf"
)

// bufPool is the process-wide buffer allocator.
var bufPool *bufAlloc

func init() {
	// Swapping buf.DefaultAllocator once relay goroutines are calling it would race, so
	// install at init, before any tunnel starts.
	bufPool = &bufAlloc{inner: buf.DefaultAllocator}
	buf.DefaultAllocator = bufPool
}

// sing-box's allocator pools power-of-two buffers from 64 B to 64 KB across these size
// classes; bufAlloc mirrors that geometry when bounding.
const (
	bufPoolMinShift = 6                                           // 1<<6 = 64 B, smallest class
	bufPoolClasses  = 11                                          // 64 B .. 64 KB
	minBufSize      = 1 << bufPoolMinShift                        // 64
	maxBufSize      = 1 << (bufPoolMinShift + bufPoolClasses - 1) // 65536
)

// relayClassLo and relayClassHi bracket the size classes holding sing-box's relay
// buffers (buf.BufferSize for TCP, buf.UDPBufferSize for UDP — both build-tag
// dependent). Only these classes are pooled under the byte budget.
var (
	relayClassLo = bufClass(min(buf.UDPBufferSize, buf.BufferSize))
	relayClassHi = bufClass(max(buf.UDPBufferSize, buf.BufferSize))
)

// bufAlloc wraps a buf.Allocator and, when setByteBudget is given a positive budget,
// bounds the total bytes of idle relay buffers it retains for reuse — dropping excess to
// GC so the pool can't grow without limit. Only the relay size classes are pooled; other
// sizes delegate to inner.
type bufAlloc struct {
	inner  buf.Allocator
	budget atomic.Int64
	pools  [bufPoolClasses]chan []byte

	retainedBytes atomic.Int64
}

// setByteBudget sets the cap on total bytes of idle relay buffers retained for reuse (0
// disables bounding). It must be called before any relay traffic begins.
func (a *bufAlloc) setByteBudget(budget int) {
	if budget > 0 {
		for idx := relayClassLo; idx <= relayClassHi; idx++ {
			// Size each free-list so the byte budget, not the channel, is the binding constraint.
			depth := budget / classSize(idx)
			if depth < 1 {
				depth = 1
			}
			a.pools[idx] = make(chan []byte, depth)
		}
	}
	// Store the budget last: Get/Put read it atomically, so publishing the free-lists first
	// keeps them from ever observing a non-zero budget with a half-built pool.
	a.budget.Store(int64(budget))
}

func (a *bufAlloc) Get(size int) []byte {
	if a.budget.Load() == 0 {
		return a.inner.Get(size)
	}
	idx, ok := relayClassForSize(size)
	if !ok {
		return a.inner.Get(size)
	}
	select {
	case b := <-a.pools[idx]:
		a.retainedBytes.Add(-int64(cap(b)))
		return b[:size]
	default:
		return make([]byte, size, classSize(idx))
	}
}

func (a *bufAlloc) Put(b []byte) error {
	if a.budget.Load() == 0 {
		return a.inner.Put(b)
	}
	c := cap(b)
	idx, ok := relayClassForCap(c)
	if !ok {
		return a.inner.Put(b)
	}
	// Reserve before the budget check and roll back if b isn't pooled, so concurrent Puts
	// can't collectively retain more than the budget.
	if a.retainedBytes.Add(int64(c)) > a.budget.Load() {
		a.retainedBytes.Add(-int64(c))
		return nil
	}
	select {
	case a.pools[idx] <- b[:c]:
	default:
		a.retainedBytes.Add(-int64(c))
	}
	return nil
}

// bufClass returns the size-class index for size: the smallest power-of-two class
// >= max(size, 64). It does not range-check, so callers must bound size to
// (0, maxBufSize] first.
func bufClass(size int) int {
	if size <= minBufSize {
		return 0
	}
	i := bits.Len32(uint32(size)) - 1
	if size != 1<<i {
		i++
	}
	return i - bufPoolMinShift
}

func classSize(idx int) int { return 1 << (idx + bufPoolMinShift) }

// relayClassForSize returns the relay class for size, with ok=false when size falls
// outside the pooled classes.
func relayClassForSize(size int) (int, bool) {
	if size <= 0 || size > maxBufSize {
		return 0, false
	}
	idx := bufClass(size)
	return idx, idx >= relayClassLo && idx <= relayClassHi
}

// relayClassForCap returns the pooled relay class a Put maps to from a buffer's cap,
// with ok=false unless cap is an exact relay-class size (an inexact cap delegates to
// inner, which validates it).
func relayClassForCap(c int) (int, bool) {
	if c < minBufSize || c > maxBufSize || c != 1<<(bits.Len32(uint32(c))-1) {
		return 0, false
	}
	idx := bits.Len32(uint32(c)) - 1 - bufPoolMinShift
	return idx, idx >= relayClassLo && idx <= relayClassHi
}

// mobileBufPoolBudget is the idle-relay-buffer byte budget applied on mobile when no
// explicit one is set. Mobile runs under a hard process-footprint cap (the iOS network
// extension is killed past ~50 MB), so the idle pool is bounded well below it; the value
// is a deliberate fraction of a measured relay working set, not the whole set, trading a
// little allocation churn for a bounded footprint.
const mobileBufPoolBudget = 4 * 1024 * 1024 // 4 MB

func defaultBufPoolBudget() int {
	if common.IsMobile() {
		return mobileBufPoolBudget
	}
	return 0
}

var bufBudgetOnce sync.Once

// configureBufPool resolves and applies the relay buffer-pool byte budget. It is safe to call
// multiple times, but only the first call has an effect; subsequent calls are no-ops. It must be
// called before any relay traffic begins.
func configureBufPool() {
	// setByteBudget rebuilds the pool free-lists, so a restart overlapping a still-draining
	// tunnel must not re-run it against live relay buffers.
	bufBudgetOnce.Do(func() {
		budget := defaultBufPoolBudget()
		if v, ok := env.Get(env.BufPoolBudgetMB); ok {
			mb, _ := strconv.Atoi(v)
			mb = max(0, mb)
			budget = mb * 1024 * 1024
		}
		bufPool.setByteBudget(budget)
	})
}
