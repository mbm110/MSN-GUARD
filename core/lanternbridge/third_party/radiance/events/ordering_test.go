package events

import (
	"reflect"
	"sync"
	"testing"
	"time"
)

type orderedEvt struct{ n int }

func (orderedEvt) IsEvent() {}

// The bug this package shipped with: Emit spawned a goroutine per callback per
// event, so nothing ordered two Emits against each other. Consumers that
// render the newest state — the share card takes the phase from whichever
// frame arrived last — settled on an arbitrary one, which is how a peer that
// had already registered kept reading "discovering public IP".
//
// Written as a loop because a single round can come out ordered by luck. The
// pre-fix implementation failed all 200.
func TestEmit_DeliversInOrderToASubscriber(t *testing.T) {
	const rounds, perRound = 200, 8

	for r := 0; r < rounds; r++ {
		var mu sync.Mutex
		got := make([]int, 0, perRound)
		done := make(chan struct{})
		sub := Subscribe(func(e orderedEvt) {
			mu.Lock()
			got = append(got, e.n)
			full := len(got) == perRound
			mu.Unlock()
			if full {
				close(done)
			}
		})

		for i := 0; i < perRound; i++ {
			Emit(orderedEvt{n: i})
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			sub.Unsubscribe()
			t.Fatalf("round %d: only %d of %d events delivered", r, len(got), perRound)
		}
		sub.Unsubscribe()

		mu.Lock()
		for i, n := range got {
			if n != i {
				mu.Unlock()
				t.Fatalf("round %d: delivered out of order: %v", r, got)
			}
		}
		mu.Unlock()
	}
}

// Ordering is per subscriber, not global: two subscribers must still run
// concurrently, or one slow consumer would stall every other one. A callback
// that blocks until the other side has finished can only pass if they do.
func TestEmit_SubscribersDoNotBlockEachOther(t *testing.T) {
	first := make(chan struct{})
	second := make(chan struct{})

	subA := Subscribe(func(orderedEvt) {
		close(first)
		<-second // held until B runs; deadlocks if delivery is serialized
	})
	defer subA.Unsubscribe()
	subB := Subscribe(func(orderedEvt) {
		<-first
		close(second)
	})
	defer subB.Unsubscribe()

	Emit(orderedEvt{})
	select {
	case <-second:
	case <-time.After(5 * time.Second):
		t.Fatal("subscribers were serialized against each other")
	}
}

// Emit must not wait for subscribers. peer.Client emits lifecycle phases from
// the goroutine bringing the session up, so an Emit that blocked on a wedged
// consumer would stall the thing being reported on.
func TestEmit_DoesNotWaitForASubscriber(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	sub := Subscribe(func(orderedEvt) { <-release })
	defer sub.Unsubscribe()

	returned := make(chan struct{})
	go func() {
		// More than the queue depth, so this also covers the drop path
		// rather than merely filling the buffer.
		for i := 0; i < queueDepth+16; i++ {
			Emit(orderedEvt{n: i})
		}
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("Emit blocked on a subscriber that was not consuming")
	}
}

// SubscribeUntil unsubscribes from inside the callback, which now runs on the
// very goroutine Unsubscribe stops. If stopping ever waited for that goroutine
// to finish, this would deadlock rather than fail.
func TestSubscribeUntil_CanUnsubscribeFromInsideItsOwnCallback(t *testing.T) {
	done := make(chan int, 4)
	SubscribeUntil(func(e orderedEvt) { done <- e.n }, func(e orderedEvt) bool { return e.n == 1 })

	Emit(orderedEvt{n: 0})
	Emit(orderedEvt{n: 1})
	Emit(orderedEvt{n: 2})

	select {
	case n := <-done:
		if n != 0 {
			t.Fatalf("first delivery was %d, want 0", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no delivery; self-unsubscribe likely deadlocked")
	}
	select {
	case n := <-done:
		if n != 1 {
			t.Fatalf("second delivery was %d, want 1", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second delivery never arrived")
	}
	// The condition matched on 1, so 2 must not arrive.
	select {
	case n := <-done:
		t.Fatalf("delivered %d after the subscription ended", n)
	case <-time.After(200 * time.Millisecond):
	}
}

// Unsubscribe must end the delivery goroutine, not merely signal it. Ordering
// required a goroutine per subscription where the package previously held
// none, so anything short of it actually returning is a leak for the process
// lifetime — and observing the stop signal alone would not have shown that.
func TestUnsubscribe_EndsTheDeliveryGoroutine(t *testing.T) {
	sub := Subscribe(func(orderedEvt) {})
	subscriptionsMu.RLock()
	s := subscriptions[reflect.TypeFor[orderedEvt]()][(*Subscription[Event])(sub)]
	subscriptionsMu.RUnlock()
	if s == nil {
		t.Fatal("subscription not registered")
	}
	sub.Unsubscribe()
	select {
	case <-s.exited:
	case <-time.After(5 * time.Second):
		t.Fatal("delivery goroutine never returned")
	}
}

// Unsubscribe must stop delivery of events already sitting in the queue, not
// just future ones. Once stopped is closed, it and a queued event are both
// ready select cases and the choice is random — so without a second check
// after dequeuing, a caller that unsubscribed could still be called back up to
// a full queue's worth of times.
//
// SubscribeUntil does not expose this: it carries its own done flag, which
// swallows the late delivery instead of preventing it. Only a plain Subscribe
// shows the behaviour.
//
// Looped, because a single round can survive the random choice by luck.
func TestUnsubscribe_DropsEventsAlreadyQueued(t *testing.T) {
	for r := 0; r < 20; r++ {
		entered := make(chan struct{})
		release := make(chan struct{})
		var mu sync.Mutex
		var got []int

		sub := Subscribe(func(e orderedEvt) {
			mu.Lock()
			got = append(got, e.n)
			first := len(got) == 1
			mu.Unlock()
			if first {
				close(entered)
				<-release // hold the goroutine inside the first delivery
			}
		})
		subscriptionsMu.RLock()
		s := subscriptions[reflect.TypeFor[orderedEvt]()][(*Subscription[Event])(sub)]
		subscriptionsMu.RUnlock()

		// Emit never blocks, so all four are queued before the callback for
		// the first one has finished.
		for i := 0; i < 4; i++ {
			Emit(orderedEvt{n: i})
		}
		<-entered
		sub.Unsubscribe()
		close(release)

		// Waiting for the goroutine to return is exact, where a sleep would
		// only be probably-long-enough — and it cannot pass by finishing
		// before a late delivery that was still coming.
		select {
		case <-s.exited:
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: delivery goroutine never returned", r)
		}
		mu.Lock()
		delivered := append([]int(nil), got...)
		mu.Unlock()
		if len(delivered) != 1 {
			t.Fatalf("round %d: delivered %v after Unsubscribe; want only [0]", r, delivered)
		}
	}
}
