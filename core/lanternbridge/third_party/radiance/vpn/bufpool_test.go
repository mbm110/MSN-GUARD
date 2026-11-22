package vpn

import (
	"testing"

	"github.com/sagernet/sing/common/buf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubAllocator struct {
	gets, puts int
}

func (s *stubAllocator) Get(size int) []byte { s.gets++; return make([]byte, size) }
func (s *stubAllocator) Put([]byte) error    { s.puts++; return nil }

func TestBufClass(t *testing.T) {
	cases := []struct {
		size, want int
	}{
		{1, 0}, {64, 0}, {65, 1}, {128, 1}, {129, 2},
		{4096, 6}, {8192, 7}, {8193, 8}, {16384, 8}, {32768, 9}, {65536, 10},
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, bufClass(c.size), "bufClass(%d)", c.size)
	}
}

func TestBufAllocUnbounded(t *testing.T) {
	stub := &stubAllocator{}
	a := &bufAlloc{inner: stub}
	a.setByteBudget(0)

	b := a.Get(buf.UDPBufferSize)
	require.NoError(t, a.Put(b))

	assert.Equal(t, 1, stub.gets, "inner.Get calls")
	assert.Equal(t, 1, stub.puts, "inner.Put calls")
}

func TestBufAllocBoundedRetention(t *testing.T) {
	relay := buf.UDPBufferSize
	stub := &stubAllocator{}
	a := &bufAlloc{inner: stub}
	a.setByteBudget(2 * relay) // room for exactly two relay buffers

	for i := 0; i < 4; i++ {
		require.NoError(t, a.Put(make([]byte, relay)))
	}
	assert.Len(t, a.pools[bufClass(relay)], 2, "retained (budget)")
	assert.Equal(t, int64(2*relay), a.retainedBytes.Load(), "retained bytes")
	assert.Zero(t, stub.puts, "inner.Put must not be used for a relay class")

	first := a.Get(relay)
	assert.Equal(t, relay, cap(first), "reused buffer cap")
	a.Get(relay)
	a.Get(relay)
	assert.Empty(t, a.pools[bufClass(relay)], "pool should be drained")
	assert.Zero(t, a.retainedBytes.Load(), "retained bytes back to zero")
	assert.Zero(t, stub.gets, "inner.Get must not be used for a relay class")
}

// The budget is shared across relay classes by total bytes, not per class: once the
// retained bytes reach the budget, further puts of any class are dropped.
func TestBufAllocByteBudgetAcrossClasses(t *testing.T) {
	lo, hi := buf.UDPBufferSize, buf.BufferSize
	require.NotEqual(t, lo, hi, "relay classes must differ")
	a := &bufAlloc{inner: &stubAllocator{}}
	a.setByteBudget(lo + hi)

	require.NoError(t, a.Put(make([]byte, hi))) // retained: hi
	require.NoError(t, a.Put(make([]byte, hi))) // hi+hi > budget -> dropped
	require.NoError(t, a.Put(make([]byte, lo))) // hi+lo == budget -> retained
	require.NoError(t, a.Put(make([]byte, lo))) // over budget -> dropped

	assert.Len(t, a.pools[bufClass(hi)], 1, "one hi-class buffer retained")
	assert.Len(t, a.pools[bufClass(lo)], 1, "one lo-class buffer retained")
	assert.Equal(t, int64(lo+hi), a.retainedBytes.Load(), "retained bytes capped at budget")
}

// Only the relay classes are pooled; every other size delegates to inner in both
// directions, leaving sing-box's allocator to handle it as before.
func TestBufAllocPoolsRelayClassesOnly(t *testing.T) {
	const nonRelay = 1024
	stub := &stubAllocator{}
	a := &bufAlloc{inner: stub}
	a.setByteBudget(1 << 20)

	a.Get(nonRelay)
	assert.Equal(t, 1, stub.gets, "non-relay Get delegates to inner")
	a.Get(buf.BufferSize)
	assert.Equal(t, 1, stub.gets, "relay Get is served without inner")

	require.NoError(t, a.Put(make([]byte, nonRelay)))
	assert.Equal(t, 1, stub.puts, "non-relay Put delegates to inner")
	require.NoError(t, a.Put(make([]byte, buf.BufferSize)))
	assert.Equal(t, 1, stub.puts, "relay Put is pooled, not delegated")
}

// Guards against drift between bufAlloc's size classes and sing-box's: a relay buffer must
// round-trip through Put into the pool and back out of Get at the same cap.
func TestBufAllocRelayRoundTrip(t *testing.T) {
	a := &bufAlloc{inner: &stubAllocator{}}
	a.setByteBudget(1 << 20)
	for _, size := range []int{buf.UDPBufferSize, buf.BufferSize} {
		require.NoErrorf(t, a.Put(make([]byte, size)), "Put(cap=%d)", size)
		got := a.Get(size)
		assert.Equalf(t, size, cap(got), "Get(%d) cap", size)
	}
}

// The mobile budget must stay well under the iOS network-extension footprint cap that
// motivates it; desktop stays unbounded.
func TestDefaultBufPoolBudget(t *testing.T) {
	const iOSFootprintCap = 50 << 20
	assert.Greater(t, mobileBufPoolBudget, 0, "mobile budget must bound the pool")
	assert.Less(t, mobileBufPoolBudget, iOSFootprintCap, "mobile budget must stay under the iOS footprint cap")
	assert.Zero(t, defaultBufPoolBudget(), "desktop test host defaults to unbounded")
}
