package log

import (
	"sync"
)

const defaultPublisherRingSize = 30

var defaultPublisher = newPublisher(defaultPublisherRingSize)

// LogEntry is a formatted log line streamed to clients.
type LogEntry = string

// Subscribe returns a channel that receives log entries from the default logger
// and an unsubscribe function. Recent entries from the ring buffer are sent
// immediately.
func Subscribe() (chan LogEntry, func()) {
	return defaultPublisher.subscribe()
}

// Publisher returns the default log publisher. Include it in the handler's
// writer chain so published entries share the same format.
func Publisher() *publisher {
	return defaultPublisher
}

// publisher fans out log lines to connected SSE clients. It implements io.Writer
// so it can be included in the handler's writer chain. It maintains a ring buffer
// of recent entries so new subscribers get immediate context.
type publisher struct {
	clients map[chan LogEntry]struct{}
	// ring retains the last ringSize entries as reused byte buffers, so the
	// backlog avoids a per-line allocation once warm.
	ring     [][]byte
	ringSize int
	ringIdx  int
	mu       sync.RWMutex
}

func newPublisher(ringSize int) *publisher {
	return &publisher{
		clients:  make(map[chan LogEntry]struct{}),
		ring:     make([][]byte, ringSize),
		ringSize: ringSize,
	}
}

// Write implements io.Writer. Each call is treated as a single log line.
func (p *publisher) Write(b []byte) (int, error) {
	p.publish(b)
	return len(b), nil
}

// publish records b in the ring and fans it out to live subscribers under one
// exclusive lock. Ring insertion and broadcast must stay atomic with respect to
// subscribe so a client subscribing concurrently observes b either in its
// backlog replay or on its live channel, never both and never neither.
func (p *publisher) publish(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	slot := p.ringIdx % p.ringSize
	p.ring[slot] = append(p.ring[slot][:0], b...)
	p.ringIdx++

	if len(p.clients) == 0 {
		return
	}
	entry := string(b)
	for ch := range p.clients {
		select {
		case ch <- entry:
		default: // drop if client is slow
		}
	}
}

func (p *publisher) subscribe() (chan LogEntry, func()) {
	ch := make(chan LogEntry, p.ringSize)
	p.mu.Lock()
	start := max(0, p.ringIdx-p.ringSize)
	for i := start; i < p.ringIdx; i++ {
		if slot := p.ring[i%p.ringSize]; len(slot) > 0 {
			ch <- string(slot)
		}
	}
	p.clients[ch] = struct{}{}
	p.mu.Unlock()

	unsub := func() {
		p.mu.Lock()
		delete(p.clients, ch)
		p.mu.Unlock()
	}
	return ch, unsub
}
