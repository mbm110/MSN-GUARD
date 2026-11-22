// Package events provides a simple publish-subscribe mechanism for event handling.
//
// This package does not define specific events; instead, publishers define their own event types
// by embedding the Event interface in their structs. Subscribers can subscribe to these custom
// events by providing callback functions that accept the event type as a parameter.
//
// Example:
//
// package somepkg
//
//	type SomeEvent struct {
//	    events.Event // embedding marks this as an event type
//	    Message string
//	}
//
//	func doSomething() {
//		events.Emit(SomeEvent{Message: "hello world"})
//	}
//
// package other
//
//	func doOtherthing() {
//		sub := events.Subscribe(func(evt somepkg.SomeEvent) {
//		    fmt.Println("Received event:", evt.Message)
//		})
//	}
package events

import (
	"context"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
)

type Event interface {
	// IsEvent is a marker method for the Event interface; it has no runtime use.
	IsEvent()
}

var (
	subscriptions   = make(map[reflect.Type]map[*Subscription[Event]]*subscriber)
	subscriptionsMu sync.RWMutex
)

// queueDepth bounds how many events can be waiting for one subscriber. Deep
// enough that it is never reached by a subscriber that is merely slow — the
// event types here fire a handful of times per user action, not per packet —
// so reaching it means the callback is wedged, not busy.
const queueDepth = 256

// subscriber owns one subscription's delivery: a single goroutine draining a
// FIFO queue, which is what orders it. Emit previously spawned a goroutine per
// event per callback, leaving the delivery order to the scheduler, so a
// consumer that renders the newest event received an arbitrary one.
type subscriber struct {
	deliver func(any)
	queue   chan any
	stopped chan struct{}
	// exited is closed when the delivery goroutine returns. Distinct from
	// stopped, which only records that it was asked to: an in-flight callback
	// still has to finish first, so the two are not the same moment and only
	// this one means the goroutine is gone.
	exited   chan struct{}
	stopOnce sync.Once
}

func newSubscriber(key reflect.Type, deliver func(any)) *subscriber {
	s := &subscriber{
		deliver: deliver,
		queue:   make(chan any, queueDepth),
		stopped: make(chan struct{}),
		exited:  make(chan struct{}),
	}
	go s.run(key)
	return s
}

func (s *subscriber) run(key reflect.Type) {
	defer close(s.exited)
	for {
		select {
		case <-s.stopped:
			return
		case evt := <-s.queue:
			// Re-checked, because reaching here does not mean the
			// subscription is still live: once stopped is closed both cases
			// are ready and select picks at random. Without this, up to a
			// full queue of callbacks could still run after Unsubscribe had
			// returned. SubscribeUntil only looks immune to that — it
			// carries its own done flag, which swallows the late delivery
			// rather than preventing it.
			select {
			case <-s.stopped:
				return
			default:
			}
			s.invoke(key, evt)
		}
	}
}

// invoke keeps the per-callback recover that Emit used to hold. Without it one
// panicking subscriber would now take down the delivery goroutine, silently
// ending that subscription rather than just losing one event.
func (s *subscriber) invoke(key reflect.Type, evt any) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic in event callback", "error", r, "event", key.String())
		}
	}()
	s.deliver(evt)
}

// enqueue never blocks. Emit has always returned without waiting on
// subscribers, and callers depend on that — emitters may call from a
// goroutine mid-session-bringup. A full queue is therefore dropped rather
// than waited on, loudly, because by then the subscriber has ignored 256
// events and waiting would only spread its problem to the emitter.
func (s *subscriber) enqueue(key reflect.Type, evt any) {
	select {
	case s.queue <- evt:
	case <-s.stopped:
	default:
		slog.Error("Dropped event: subscriber is not draining its queue",
			"event", key.String(), "queue_depth", queueDepth)
	}
}

func (s *subscriber) stop() {
	s.stopOnce.Do(func() { close(s.stopped) })
}

// Subscription allows unsubscribing from an event.
type Subscription[T Event] struct {
	_ byte // padding to avoid empty struct optimizations
}

// Subscribe registers a callback function for the given event type T. Returns a Subscription handle
// that can be used to unsubscribe later.
func Subscribe[T Event](callback func(evt T)) *Subscription[T] {
	subscriptionsMu.Lock()
	defer subscriptionsMu.Unlock()
	key := reflect.TypeFor[T]()
	if subscriptions[key] == nil {
		subscriptions[key] = make(map[*Subscription[Event]]*subscriber)
	}
	sub := &Subscription[T]{}
	subscriptions[key][(*Subscription[Event])(sub)] = newSubscriber(key, func(e any) { callback(e.(T)) })
	return sub
}

// SubscribeOnce registers a callback function for the given event type T that will be invoked only
// once. Returns a Subscription handle that can be used to unsubscribe if needed.
func SubscribeOnce[T Event](callback func(evt T)) *Subscription[T] {
	return SubscribeUntil(callback, func(evt T) bool { return true })
}

// SubscribeUntil registers a callback function for the given event type T that will be invoked until
// the provided condition function returns true for an event. Returns a Subscription handle that can
// be used to unsubscribe if needed.
func SubscribeUntil[T Event](callback func(evt T), cond func(evt T) bool) *Subscription[T] {
	var done atomic.Bool
	var sub *Subscription[T]
	sub = Subscribe(func(evt T) {
		if done.Load() {
			return
		}
		callback(evt)
		if cond(evt) {
			done.Store(true)
			sub.Unsubscribe()
		}
	})
	return sub
}

// SubscribeContext registers a callback for event type T that is automatically unsubscribed when
// the provided context is cancelled.
func SubscribeContext[T Event](ctx context.Context, callback func(evt T)) *Subscription[T] {
	sub := Subscribe(callback)
	go func() {
		<-ctx.Done()
		sub.Unsubscribe()
	}()
	return sub
}

// Unsubscribe removes the given subscription.
func Unsubscribe[T Event](sub *Subscription[T]) {
	subscriptionsMu.Lock()
	defer subscriptionsMu.Unlock()
	key := reflect.TypeFor[T]()
	if subs, ok := subscriptions[key]; ok {
		if s, found := subs[(*Subscription[Event])(sub)]; found {
			// Non-blocking, so a callback may unsubscribe itself —
			// SubscribeUntil does exactly that, from the delivery goroutine
			// this stops.
			s.stop()
		}
		delete(subs, (*Subscription[Event])(sub))
		if len(subs) == 0 {
			delete(subscriptions, key)
		}
	}
}

func (e *Subscription[T]) Unsubscribe() {
	Unsubscribe(e)
}

// Emit notifies all subscribers of the event, passing event data. It does not wait for them.
//
// Each subscriber receives events in the order they were emitted. Different
// subscribers still run concurrently with each other; only one subscriber's
// own callbacks are serialized.
func Emit[T Event](evt T) {
	key := reflect.TypeFor[T]()
	// Snapshot the subscribers into a slice under the RLock, then drop
	// the lock before doing anything that could block (the diagnostic
	// log, the enqueue to each one). Iterating the underlying
	// map after releasing the lock would race against Unsubscribe's
	// write lock — `concurrent map iteration and map write` panic
	// territory under load.
	subscriptionsMu.RLock()
	subsMap := subscriptions[key]
	subs := make([]*subscriber, 0, len(subsMap))
	for _, s := range subsMap {
		subs = append(subs, s)
	}
	subscriptionsMu.RUnlock()
	// Diagnostic hook; default no-op so high-frequency event types
	// don't flood logs in prod. Tests / debugging swap in a real
	// logger via SetEmitDebugLogger.
	if fn := emitDebugLogger.Load(); fn != nil {
		(*fn)(key, len(subs))
	}
	for _, s := range subs {
		s.enqueue(key, evt)
	}
}

// emitDebugLogger holds the hook invoked once per Emit with the event type
// and current subscriber count; nil means no-op. Held atomically because
// Emit reads it from arbitrary goroutines — long-lived emitters emit for the
// process lifetime, so any post-startup SetEmitDebugLogger would otherwise
// race an in-flight Emit.
var emitDebugLogger atomic.Pointer[func(reflect.Type, int)]

// SetEmitDebugLogger replaces the no-op diagnostic hook for the
// duration of an investigation (e.g., tracking "events vanish" paths).
// Pass nil to restore the no-op default. Safe to call concurrently with
// Emit.
func SetEmitDebugLogger(fn func(eventType reflect.Type, subscriberCount int)) {
	if fn == nil {
		emitDebugLogger.Store(nil)
		return
	}
	emitDebugLogger.Store(&fn)
}
