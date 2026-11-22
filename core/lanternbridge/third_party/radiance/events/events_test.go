package events

import (
	"reflect"
	"sync"
	"testing"
)

type debugHookEvent struct{}

func (debugHookEvent) IsEvent() {}

// TestSetEmitDebugLogger_SafeConcurrentlyWithEmit checks that installing the
// hook is safe against a concurrent Emit. peer.Client's heartbeat and rotation
// loops emit for the whole process lifetime, so any post-startup call to
// install the hook overlaps an in-flight Emit — and an unsynchronized write to
// a function-valued global racing a read is a data race, which `go test -race`
// fails on. Run with -race for this to be meaningful; without it, the test
// only shows neither side crashes.
func TestSetEmitDebugLogger_SafeConcurrentlyWithEmit(t *testing.T) {
	t.Cleanup(func() { SetEmitDebugLogger(nil) })

	sub := Subscribe(func(debugHookEvent) {})
	t.Cleanup(sub.Unsubscribe)

	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range iterations {
			Emit(debugHookEvent{})
		}
	}()
	go func() {
		defer wg.Done()
		for i := range iterations {
			if i%2 == 0 {
				SetEmitDebugLogger(func(reflect.Type, int) {})
			} else {
				SetEmitDebugLogger(nil)
			}
		}
	}()

	wg.Wait()
}

// TestSetEmitDebugLogger_ReceivesTypeAndCountThenClears checks that the
// installed hook receives the event type and subscriber count, and that
// clearing it stops delivery — otherwise the atomic swap could "fix" the race
// by silently never invoking the hook.
func TestSetEmitDebugLogger_ReceivesTypeAndCountThenClears(t *testing.T) {
	t.Cleanup(func() { SetEmitDebugLogger(nil) })

	sub := Subscribe(func(debugHookEvent) {})
	t.Cleanup(sub.Unsubscribe)

	var (
		mu     sync.Mutex
		types  []reflect.Type
		counts []int
	)
	SetEmitDebugLogger(func(evtType reflect.Type, subscriberCount int) {
		mu.Lock()
		defer mu.Unlock()
		types = append(types, evtType)
		counts = append(counts, subscriberCount)
	})

	Emit(debugHookEvent{})

	mu.Lock()
	if len(types) != 1 {
		mu.Unlock()
		t.Fatalf("hook should have fired exactly once, got %d calls", len(types))
	}
	if want := reflect.TypeFor[debugHookEvent](); types[0] != want {
		mu.Unlock()
		t.Fatalf("hook got event type %v, want %v", types[0], want)
	}
	if counts[0] != 1 {
		mu.Unlock()
		t.Fatalf("hook got subscriber count %d, want 1", counts[0])
	}
	mu.Unlock()

	SetEmitDebugLogger(nil)
	Emit(debugHookEvent{})

	mu.Lock()
	defer mu.Unlock()
	if len(types) != 1 {
		t.Fatalf("hook fired after being cleared: %d total calls", len(types))
	}
}
