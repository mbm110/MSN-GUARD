package account

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/traces"
)

type sseEvent struct {
	Type string
	Data string
}

const (
	// healthyStreamDuration is the minimum time a stream must stay healthy before a
	// later drop is treated as transient and allowed to reset reconnect backoff.
	healthyStreamDuration = 5 * time.Minute

	// exhaustedRetryFallback is used when the reset time is unknown.
	exhaustedRetryFallback = time.Hour

	// minExhaustedRetry prevents a tight reconnect loop if the reset time is
	// already in the past.
	minExhaustedRetry = time.Minute

	// exhaustedRetryGrace waits just past the reported reset time.
	exhaustedRetryGrace = 30 * time.Second

	// datacapDisabledRetry is how long to pause before rechecking after the
	// server reports datacap is disabled for this device. This state rarely
	// changes, so recheck infrequently.
	datacapDisabledRetry = time.Hour
)

// ErrCapExhausted marks a deliberate server close after the daily allotment is
// spent.
var ErrCapExhausted = errors.New("datacap exhausted")

type dataCapStreamState struct {
	logger       *slog.Logger
	progressed   bool
	enabled      bool
	allotmentEnd time.Time
}

// wrap records stream progress, whether datacap is enabled, and the latest
// allotment end time before calling the caller-provided handler.
func (s *dataCapStreamState) wrap(handler func(*DataCapInfo)) func(*DataCapInfo) {
	return func(info *DataCapInfo) {
		s.progressed = true
		s.enabled = info.Enabled
		s.allotmentEnd = parseAllotmentEnd(s.logger, info.Usage)
		handler(info)
	}
}

// parseAllotmentEnd extracts and parses the reset time from usage data.
func parseAllotmentEnd(logger *slog.Logger, usage *DataCapUsageDetails) time.Time {
	if usage == nil || usage.AllotmentEndTime == "" {
		return time.Time{}
	}

	t, err := time.Parse(time.RFC3339, usage.AllotmentEndTime)
	if err != nil {
		logger.Warn("datacap allotmentEndTime parse failed", "value", usage.AllotmentEndTime, "error", err)
		return time.Time{}
	}
	return t
}

// readSSE reads Server-Sent Events from body and sends parsed events on the
// returned channel. The channel is closed when the body returns EOF, an error
// occurs, or ctx is cancelled. The caller is responsible for closing body.
// After the channel is closed, call the returned function to retrieve any
// scanner error (nil on clean EOF).
func readSSE(ctx context.Context, body io.Reader) (<-chan sseEvent, func() error) {
	ch := make(chan sseEvent, 1)
	var scanErr error
	go func() {
		defer close(ch)
		scanner := bufio.NewScanner(body)
		// The initial buffer stays small to bound resident memory; the 1 MiB max still
		// admits a rare oversized line rather than failing it.
		buf := make([]byte, 0, 4*1024)
		scanner.Buffer(buf, 1024*1024)

		var evt sseEvent
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "event:"):
				evt.Type = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				dataLine := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				if evt.Data == "" {
					evt.Data = dataLine
				} else {
					evt.Data = evt.Data + "\n" + dataLine
				}
			case strings.HasPrefix(line, ":"):
				// comment / heartbeat — ignore
			case line == "":
				// blank line = event delimiter
				if evt.Type != "" || evt.Data != "" {
					select {
					case ch <- evt:
					case <-ctx.Done():
						return
					}
					evt = sseEvent{}
				}
			}
		}
		scanErr = scanner.Err()
	}()
	return ch, func() error { return scanErr }
}

// DataCapStream connects to the datacap SSE endpoint and keeps reconnecting on
// stream errors. If the server closes with cap_exhausted, it waits for the
// allotment reset instead of retrying immediately.
func (a *Client) DataCapStream(ctx context.Context, handler func(*DataCapInfo)) error {
	bo := common.NewBackoff(0, 2*time.Minute)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		start := time.Now()
		state := dataCapStreamState{logger: a.logger}

		err := a.connectDataCapSSE(ctx, state.wrap(handler))
		if err != nil {
			a.logger.Debug("datacap SSE stream ended", "error", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		if errors.Is(err, ErrCapExhausted) {
			if err := a.waitForAllotmentReset(ctx, state.allotmentEnd); err != nil {
				return err
			}
			bo.Reset()
			continue
		}

		// Datacap disabled: the server sends a single Enabled:false event and
		// closes. Recheck on a long interval rather than reconnecting into an
		// immediate close.
		if state.progressed && !state.enabled {
			a.logger.Info("datacap disabled; pausing before recheck", "retryIn", datacapDisabledRetry)
			if err := waitOrDone(ctx, datacapDisabledRetry); err != nil {
				return err
			}
			bo.Reset()
			continue
		}

		// Only streams that made progress and stayed up long enough reset
		// backoff. Early failures keep backing off.
		if streamWasHealthy(state.progressed, time.Since(start)) {
			bo.Reset()
		}
		bo.Wait(ctx)
	}
}

// streamWasHealthy reports whether a disconnected stream should be treated as a
// transient failure for backoff purposes.
func streamWasHealthy(progressed bool, upFor time.Duration) bool {
	return progressed && upFor > healthyStreamDuration
}

// allotmentResetWait returns how long to wait before reconnecting after a
// cap_exhausted close.
func allotmentResetWait(allotmentEnd time.Time) time.Duration {
	if allotmentEnd.IsZero() {
		return exhaustedRetryFallback
	}
	return max(time.Until(allotmentEnd)+exhaustedRetryGrace, minExhaustedRetry)
}

// waitForAllotmentReset blocks until the next expected reset time or until the
// context is cancelled.
func (a *Client) waitForAllotmentReset(ctx context.Context, allotmentEnd time.Time) error {
	wait := allotmentResetWait(allotmentEnd)
	a.logger.Info("datacap exhausted; waiting for allotment reset", "wait", wait, "allotmentEnd", allotmentEnd)
	return waitOrDone(ctx, wait)
}

// waitOrDone blocks for d or until ctx is cancelled, returning ctx.Err() on
// cancellation and nil once d elapses.
func waitOrDone(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// connectDataCapSSE opens an SSE connection to the datacap stream endpoint and
// processes events until the stream ends or ctx is cancelled. It returns
// ErrCapExhausted when the server closes after the daily allotment is spent, so
// the caller waits for the reset instead of reconnecting immediately.
func (a *Client) connectDataCapSSE(ctx context.Context, handler func(*DataCapInfo)) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "datacap_sse")
	defer span.End()

	sseURL := fmt.Sprintf("%s/stream/datacap/%s", a.baseURL(), settings.GetString(settings.DeviceIDKey))
	req, err := common.NewRequestWithHeaders(ctx, http.MethodGet, sseURL, nil)
	if err != nil {
		return traces.RecordError(ctx, fmt.Errorf("datacap SSE request: %w", err))
	}
	req.Header.Set(common.AcceptHeader, "text/event-stream")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return traces.RecordError(ctx, fmt.Errorf("datacap SSE connect: %w", withoutURL(err)))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return traces.RecordError(ctx, fmt.Errorf("datacap SSE status %d", resp.StatusCode))
	}

	a.logger.Debug("connected to datacap SSE stream")

	eventCh, scanErr := readSSE(ctx, resp.Body)
	var (
		last         DataCapInfo
		hasLast      bool
		capExhausted bool
	)
	for evt := range eventCh {
		switch evt.Type {
		case "datacap":
			var datacap DataCapInfo
			if err := json.Unmarshal([]byte(evt.Data), &datacap); err != nil {
				// Log only a short prefix so malformed payloads are diagnosable
				// without dumping the full response.
				prefix := evt.Data
				if len(prefix) > 64 {
					prefix = prefix[:64]
				}
				a.logger.Warn("datacap SSE payload not valid JSON", "error", err, "payloadPrefix", prefix)
				continue
			}

			last = datacap
			hasLast = true
			handler(&datacap)

			if datacap.Usage != nil {
				a.logger.Debug("datacap updated", "bytesUsed", datacap.Usage.BytesUsed)
			}
		case "cap_exhausted":
			a.logger.Log(nil, log.LevelTrace, "datacap SSE cap_exhausted event received")
			// The server closes intentionally after this event. Re-emit the last
			// known datacap state with Exhausted set so callers get the reset time.
			capExhausted = true

			exhausted := DataCapInfo{Exhausted: true}
			if hasLast {
				exhausted = last
				exhausted.Exhausted = true
			}
			handler(&exhausted)
		default:
			// heartbeat or unknown event — ignore
		}
	}
	if err := ctx.Err(); err != nil {
		return traces.RecordError(ctx, err)
	}
	if capExhausted {
		return ErrCapExhausted
	}
	if err := scanErr(); err != nil {
		return traces.RecordError(ctx, fmt.Errorf("datacap SSE scanner: %w", err))
	}
	return io.EOF
}
