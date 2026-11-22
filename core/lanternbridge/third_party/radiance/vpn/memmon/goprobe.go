package memmon

import "runtime/metrics"

// mTotal and related runtime/metrics names are read without a stop-the-world
// pause, which is why the sampler uses them on its hot path.
const (
	mTotal      = "/memory/classes/total:bytes"
	mReleased   = "/memory/classes/heap/released:bytes"
	mHeapObj    = "/memory/classes/heap/objects:bytes"
	mStacks     = "/memory/classes/heap/stacks:bytes"
	mGoroutines = "/sched/goroutines:goroutines"
	mGCCycles   = "/gc/cycles/total:gc-cycles"
)

// goSampler reads the Go runtime memory metrics. The samples slice is allocated
// once and reused, so a tick adds no garbage.
type goSampler struct {
	samples []metrics.Sample
}

func newGoSampler() *goSampler {
	return &goSampler{samples: []metrics.Sample{
		{Name: mTotal}, {Name: mReleased}, {Name: mHeapObj},
		{Name: mStacks}, {Name: mGoroutines}, {Name: mGCCycles},
	}}
}

// read returns the Go contribution to RSS (total mapped − heap released, the
// quantity GOMEMLIMIT is enforced against) and the full breakdown for the dump.
func (g *goSampler) read() (goBytes uint64, st GoStats) {
	metrics.Read(g.samples)
	total := g.samples[0].Value.Uint64()
	released := g.samples[1].Value.Uint64()
	st = GoStats{
		TotalSys:     total,
		HeapReleased: released,
		HeapObjects:  g.samples[2].Value.Uint64(),
		Stacks:       g.samples[3].Value.Uint64(),
		Goroutines:   g.samples[4].Value.Uint64(),
		NumGC:        g.samples[5].Value.Uint64(),
	}
	return total - released, st
}
