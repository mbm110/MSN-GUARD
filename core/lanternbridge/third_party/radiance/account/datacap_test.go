package account

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/log"
)

func TestReadSSE_BasicEvent(t *testing.T) {
	body := io.NopCloser(strings.NewReader("event: datacap\ndata: {\"enabled\":true}\n\n"))
	ctx := context.Background()
	ch, scanErr := readSSE(ctx, body)

	evt, ok := <-ch
	require.True(t, ok)
	assert.Equal(t, "datacap", evt.Type)
	assert.Equal(t, `{"enabled":true}`, evt.Data)

	// Channel should be closed after EOF.
	_, ok = <-ch
	assert.False(t, ok)
	assert.NoError(t, scanErr())
}

func TestReadSSE_MultipleEvents(t *testing.T) {
	input := "event: datacap\ndata: {\"enabled\":true}\n\nevent: cap_exhausted\ndata: \n\n"
	body := io.NopCloser(strings.NewReader(input))
	ctx := context.Background()
	ch, _ := readSSE(ctx, body)

	evt1 := <-ch
	assert.Equal(t, "datacap", evt1.Type)
	assert.Equal(t, `{"enabled":true}`, evt1.Data)

	evt2 := <-ch
	assert.Equal(t, "cap_exhausted", evt2.Type)
}

func TestReadSSE_MultiLineData(t *testing.T) {
	// Per SSE spec, multiple data: lines are concatenated with \n.
	input := "event: datacap\ndata: line1\ndata: line2\ndata: line3\n\n"
	body := io.NopCloser(strings.NewReader(input))
	ctx := context.Background()
	ch, scanErr := readSSE(ctx, body)

	evt := <-ch
	assert.Equal(t, "datacap", evt.Type)
	assert.Equal(t, "line1\nline2\nline3", evt.Data)

	_, ok := <-ch
	assert.False(t, ok)
	assert.NoError(t, scanErr())
}

func TestReadSSE_HeartbeatIgnored(t *testing.T) {
	// Heartbeat comment followed by a real event.
	input := ": heartbeat\n\nevent: datacap\ndata: {}\n\n"
	body := io.NopCloser(strings.NewReader(input))
	ctx := context.Background()
	ch, _ := readSSE(ctx, body)

	evt := <-ch
	assert.Equal(t, "datacap", evt.Type)
	assert.Equal(t, "{}", evt.Data)
}

func TestReadSSE_ContextCancellation(t *testing.T) {
	// Use a pipe so the reader blocks until we cancel. Closing the writer
	// simulates what the HTTP transport does when the request context is
	// cancelled (the underlying connection is severed, unblocking Read).
	pr, pw := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	ch, _ := readSSE(ctx, pr)

	cancel()
	pw.Close() // unblocks the blocked Read, like HTTP transport would

	// Channel should close promptly.
	select {
	case _, ok := <-ch:
		assert.False(t, ok)
	case <-time.After(2 * time.Second):
		t.Fatal("channel did not close after context cancellation")
	}
}

func TestReadSSE_EmptyLinesIgnored(t *testing.T) {
	// Multiple blank lines should not produce empty events.
	input := "\n\n\nevent: datacap\ndata: ok\n\n"
	body := io.NopCloser(strings.NewReader(input))
	ctx := context.Background()
	ch, _ := readSSE(ctx, body)

	evt := <-ch
	assert.Equal(t, "datacap", evt.Type)
	assert.Equal(t, "ok", evt.Data)

	_, ok := <-ch
	assert.False(t, ok)
}

func TestConnectDataCapSSE_CapExhausted(t *testing.T) {
	const endTime = "2026-08-13T00:00:00Z"
	body := "event: datacap\n" +
		`data: {"enabled":true,"usage":{"bytesAllotted":"100","bytesUsed":"100","allotmentEndTime":"` + endTime + `"}}` + "\n\n" +
		"event: cap_exhausted\ndata: device123\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, body)
	}))
	defer srv.Close()

	a := &Client{httpClient: srv.Client(), logger: log.NoOpLogger(), authURL: srv.URL}
	var got []DataCapInfo
	err := a.connectDataCapSSE(context.Background(), func(info *DataCapInfo) {
		got = append(got, *info)
	})

	assert.ErrorIs(t, err, ErrCapExhausted)
	require.Len(t, got, 2)
	assert.False(t, got[0].Exhausted)
	assert.True(t, got[1].Exhausted, "cap_exhausted must re-emit the info with Exhausted set")
	require.NotNil(t, got[1].Usage)
	assert.Equal(t, endTime, got[1].Usage.AllotmentEndTime, "exhausted info must carry the reset time from the preceding datacap event")
}

func TestWaitForAllotmentReset_ContextCancelled(t *testing.T) {
	a := &Client{logger: log.NoOpLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A cancelled context must return immediately even when the fallback wait
	// would otherwise be long.
	err := a.waitForAllotmentReset(ctx, time.Time{})
	assert.ErrorIs(t, err, context.Canceled)
}

func TestAllotmentResetWait(t *testing.T) {
	now := time.Now()

	// Unknown reset time falls back to the fixed poll.
	assert.Equal(t, exhaustedRetryFallback, allotmentResetWait(time.Time{}))

	// A future reset time waits until just past it.
	future := allotmentResetWait(now.Add(time.Hour))
	assert.InDelta(t, (time.Hour + 30*time.Second).Seconds(), future.Seconds(), 2)

	// A reset time already in the past retries promptly, not after the fallback.
	assert.Equal(t, minExhaustedRetry, allotmentResetWait(now.Add(-time.Hour)))
}

func TestDataCapStreamState_Wrap(t *testing.T) {
	s := dataCapStreamState{logger: log.NoOpLogger()}
	var delivered bool
	h := s.wrap(func(*DataCapInfo) { delivered = true })

	h(&DataCapInfo{
		Enabled: false,
		Usage:   &DataCapUsageDetails{AllotmentEndTime: "2026-08-13T00:00:00Z"},
	})

	assert.True(t, delivered, "wrap must call the wrapped handler")
	assert.True(t, s.progressed)
	assert.False(t, s.enabled, "Enabled:false must be recorded so DataCapStream can pause")
	assert.False(t, s.allotmentEnd.IsZero(), "a valid AllotmentEndTime must be parsed")
}

func TestStreamWasHealthy(t *testing.T) {
	// The reset must key on progress AND a duration well past the server's
	// update cadence; a stream that dies near the cadence must not reset.
	assert.False(t, streamWasHealthy(false, healthyStreamDuration+time.Minute), "no event received")
	assert.False(t, streamWasHealthy(true, 31*time.Second), "died near the 30s update cadence")
	assert.False(t, streamWasHealthy(true, healthyStreamDuration), "exactly at threshold is not past it")
	assert.True(t, streamWasHealthy(true, healthyStreamDuration+time.Second), "long-lived stream with progress")
}

func TestReadSSE_ScannerError(t *testing.T) {
	// Feed a line longer than the scanner buffer to trigger ErrTooLong.
	// Default scanner buffer is 64KB; our readSSE uses 1MB max.
	// Create a line just over 1MB to trigger the error.
	longLine := "data: " + strings.Repeat("x", 1024*1024+1) + "\n\n"
	body := io.NopCloser(strings.NewReader(longLine))
	ctx := context.Background()
	ch, scanErr := readSSE(ctx, body)

	// Drain the channel.
	for range ch {
	}

	// Scanner should have errored.
	assert.Error(t, scanErr())
}
