package memmon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type noopExecutor struct{}

func (noopExecutor) Apply(Decision, time.Time) {}

type countingExecutor struct {
	n atomic.Int32
}

func (c *countingExecutor) Apply(Decision, time.Time) {
	c.n.Add(1)
}

func (c *countingExecutor) count() int {
	return int(c.n.Load())
}

func TestStepNilExecutorSafe(t *testing.T) {
	fs := &fakeSampler{pressure: 0.1}
	mon := New(Config{BaseInterval: time.Millisecond}, fs, nil)
	require.NotPanics(t, func() { mon.Step(gateBase) })

	mon.SetExecutor(nil)
	require.NotPanics(t, func() { mon.Step(gateBase) })
}

func TestSetExecutorAppliesOnLaterTicks(t *testing.T) {
	fs := &fakeSampler{pressure: 0.1}
	mon := New(Config{BaseInterval: time.Millisecond}, fs, nil)

	exec := &countingExecutor{}
	mon.Step(gateBase)
	require.Equal(t, 0, exec.count(), "nil executor must not be applied")

	mon.SetExecutor(exec)
	mon.Step(gateBase.Add(time.Millisecond))
	require.Equal(t, 1, exec.count(), "installed executor is applied on the next tick")
}

func TestRunTicksThenStopsOnCancel(t *testing.T) {
	fs := &fakeSampler{pressure: 0.1} // Normal level → reschedule at BaseInterval
	mon := New(Config{BaseInterval: time.Millisecond}, fs, noopExecutor{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mon.Run(ctx)
		close(done)
	}()

	require.Eventually(t, func() bool { return fs.sampleCount() >= 3 }, time.Second, time.Millisecond,
		"Run samples on each timer tick and reschedules")

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}
