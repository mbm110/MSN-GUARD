package log

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublisher(t *testing.T) {
	p := newPublisher(10)

	ch, unsub := p.subscribe()
	defer unsub()

	entry := "time=2025-01-01T00:00:00.000Z level=INFO msg=hello\n"
	p.publish([]byte(entry))

	select {
	case got := <-ch:
		assert.Equal(t, entry, got)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for broadcast")
	}
}

func TestPublisherWrite(t *testing.T) {
	p := newPublisher(10)

	ch, unsub := p.subscribe()
	defer unsub()

	line := "time=2025-01-01T00:00:00.000Z level=INFO msg=hello\n"
	n, err := p.Write([]byte(line))
	require.NoError(t, err)
	assert.Equal(t, len(line), n)

	select {
	case got := <-ch:
		assert.Equal(t, line, got)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for broadcast")
	}
}

func TestMultipleSubscribers(t *testing.T) {
	p := newPublisher(10)

	ch1, unsub1 := p.subscribe()
	defer unsub1()
	ch2, unsub2 := p.subscribe()
	defer unsub2()

	entry := "time=2025-01-01T00:00:00.000Z level=DEBUG msg=multi\n"
	p.publish([]byte(entry))

	for _, ch := range []chan LogEntry{ch1, ch2} {
		select {
		case got := <-ch:
			assert.Equal(t, entry, got)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for broadcast")
		}
	}
}

func TestUnsubscribe(t *testing.T) {
	p := newPublisher(10)

	ch, unsub := p.subscribe()
	unsub()

	p.publish([]byte("time=2025-01-01T00:00:00.000Z level=INFO msg=\"after unsub\"\n"))

	select {
	case <-ch:
		t.Fatal("should not receive after unsubscribe")
	case <-time.After(50 * time.Millisecond):
		// expected
	}
}

func TestRingBuffer(t *testing.T) {
	p := newPublisher(3)

	// Fill the ring buffer with 5 entries, so only the last 3 should be available.
	for i := range 5 {
		p.publish([]byte(string(rune('a'+i)) + "\n"))
	}

	ch, unsub := p.subscribe()
	defer unsub()

	// New subscriber should get the 3 ring buffer entries.
	var msgs []string
	for range 3 {
		select {
		case e := <-ch:
			msgs = append(msgs, e)
		case <-time.After(time.Second):
			t.Fatal("timed out reading ring buffer entries")
		}
	}
	assert.Equal(t, []string{"c\n", "d\n", "e\n"}, msgs)
}

func TestConcurrentBroadcast(t *testing.T) {
	p := newPublisher(100)
	ch, unsub := p.subscribe()
	defer unsub()

	var wg sync.WaitGroup
	n := 50
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			p.publish([]byte("msg\n"))
		}(i)
	}
	wg.Wait()

	received := 0
	for {
		select {
		case <-ch:
			received++
		default:
			require.Equal(t, n, received)
			return
		}
	}
}
