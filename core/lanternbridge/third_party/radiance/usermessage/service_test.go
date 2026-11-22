package usermessage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	wire "github.com/getlantern/common/usermessage"
	"github.com/getlantern/radiance/events"
)

func TestServicePollingBackoffAndSuccessReset(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC))
	fetcher := newScriptedFetcher()
	service := newTestService(t, clock, fetcher, func() ClientContext { return testClientContext() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service.Start(ctx)

	receiveFetch(t, fetcher)
	fetcher.results <- fetchResult{err: errors.New("offline")}
	require.Equal(t, 5*time.Second, receiveTimer(t, clock))
	clock.Advance(5 * time.Second)

	receiveFetch(t, fetcher)
	fetcher.results <- fetchResult{err: errors.New("still offline")}
	require.Equal(t, 10*time.Second, receiveTimer(t, clock))
	clock.Advance(10 * time.Second)

	receiveFetch(t, fetcher)
	fetcher.results <- fetchResult{response: wire.UserMessageResponse{PollIntervalSeconds: 300}}
	require.Equal(t, 5*time.Minute, receiveTimer(t, clock))
	clock.Advance(5 * time.Minute)

	receiveFetch(t, fetcher)
	fetcher.results <- fetchResult{err: errors.New("failed after success")}
	require.Equal(t, 5*time.Second, receiveTimer(t, clock))
}

func TestServiceRespectsSuccessfulPollIntervalWithoutJitter(t *testing.T) {
	clock := newFakeClock(time.Now())
	fetcher := newScriptedFetcher()
	service, err := newService(Options{
		DataDir:         t.TempDir(),
		Fetcher:         fetcher,
		ContextProvider: func() ClientContext { return testClientContext() },
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, dependencies{
		clock:  clock,
		jitter: func(delay time.Duration) time.Duration { return delay / 2 },
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service.Start(ctx)

	receiveFetch(t, fetcher)
	fetcher.results <- fetchResult{response: wire.UserMessageResponse{PollIntervalSeconds: 300}}
	require.Equal(t, 5*time.Minute, receiveTimer(t, clock))
	clock.Advance(5 * time.Minute)

	receiveFetch(t, fetcher)
	fetcher.results <- fetchResult{err: errors.New("offline")}
	require.Equal(t, 2500*time.Millisecond, receiveTimer(t, clock))
}

func TestServiceImmediateRefreshForContextAndActivityChanges(t *testing.T) {
	clock := newFakeClock(time.Now())
	fetcher := newScriptedFetcher()
	var mu sync.Mutex
	clientContext := testClientContext()
	provider := func() ClientContext {
		mu.Lock()
		defer mu.Unlock()
		return clientContext
	}
	service := newTestService(t, clock, fetcher, provider)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service.Start(ctx)

	require.Equal(t, "fa-IR", receiveFetch(t, fetcher).clientContext.Locale)
	fetcher.results <- fetchResult{response: wire.UserMessageResponse{PollIntervalSeconds: 300}}
	receiveTimer(t, clock)

	mu.Lock()
	clientContext.Locale = "en-US"
	mu.Unlock()
	service.Refresh()
	require.Equal(t, "en-US", receiveFetch(t, fetcher).clientContext.Locale)
	fetcher.results <- fetchResult{response: wire.UserMessageResponse{PollIntervalSeconds: 300}}
	receiveTimer(t, clock)

	service.SetActivity(false)
	require.Never(t, func() bool {
		select {
		case <-fetcher.requests:
			return true
		default:
			return false
		}
	}, 50*time.Millisecond, time.Millisecond)
	service.SetActivity(true)
	require.Equal(t, "en-US", receiveFetch(t, fetcher).clientContext.Locale)
}

func TestServiceSeenFilteringAccountSwitchAndExpiration(t *testing.T) {
	clock := newFakeClock(time.Now())
	fetcher := newScriptedFetcher()
	var mu sync.Mutex
	clientContext := testClientContext()
	provider := func() ClientContext {
		mu.Lock()
		defer mu.Unlock()
		return clientContext
	}
	service := newTestService(t, clock, fetcher, provider)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service.Start(ctx)

	first := receiveFetch(t, fetcher)
	require.Empty(t, first.seen)
	fetcher.results <- fetchResult{response: wire.UserMessageResponse{
		PollIntervalSeconds: 300,
		Message:             testMessage("display-1", clock.Now().Add(time.Minute)),
	}}
	receiveTimer(t, clock)
	message, err := service.Current()
	require.NoError(t, err)
	require.Equal(t, "display-1", message.DisplayID)
	require.NoError(t, service.Acknowledge("display-1", clientContext.UserID))
	request := receiveFetch(t, fetcher)
	require.Equal(t, []string{"display-1"}, request.seen)
	fetcher.results <- fetchResult{response: wire.UserMessageResponse{PollIntervalSeconds: 300}}
	receiveTimer(t, clock)

	mu.Lock()
	clientContext.UserID = "67890"
	mu.Unlock()
	service.Refresh()
	request = receiveFetch(t, fetcher)
	require.Empty(t, request.seen)
	fetcher.results <- fetchResult{response: wire.UserMessageResponse{
		PollIntervalSeconds: 300,
		Message:             testMessage("display-2", clock.Now().Add(time.Minute)),
	}}
	receiveTimer(t, clock)
	clock.Advance(time.Minute)
	message, err = service.Current()
	require.NoError(t, err)
	require.Nil(t, message)
}

func TestServiceEmitsAvailabilityAfterPersistingMessage(t *testing.T) {
	clock := newFakeClock(time.Now())
	fetcher := newScriptedFetcher()
	service := newTestService(t, clock, fetcher, func() ClientContext { return testClientContext() })
	available := make(chan struct{}, 1)
	sub := events.Subscribe(func(AvailableEvent) { available <- struct{}{} })
	t.Cleanup(sub.Unsubscribe)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service.Start(ctx)

	receiveFetch(t, fetcher)
	fetcher.results <- fetchResult{response: wire.UserMessageResponse{
		PollIntervalSeconds: 300,
		Message:             testMessage("display-1", clock.Now().Add(time.Hour)),
	}}
	receiveTimer(t, clock)
	select {
	case <-available:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for availability event")
	}
	message, err := service.Current()
	require.NoError(t, err)
	require.Equal(t, "display-1", message.DisplayID)
}

func TestServiceDiscardsUnsupportedMessage(t *testing.T) {
	clock := newFakeClock(time.Now())
	fetcher := newScriptedFetcher()
	service := newTestService(t, clock, fetcher, func() ClientContext { return testClientContext() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service.Start(ctx)

	message := testMessage("display-1", clock.Now().Add(time.Hour))
	message.Surface = "future_surface"
	receiveFetch(t, fetcher)
	fetcher.results <- fetchResult{response: wire.UserMessageResponse{
		PollIntervalSeconds: 300,
		Message:             message,
	}}
	receiveTimer(t, clock)
	current, err := service.Current()
	require.NoError(t, err)
	require.Nil(t, current)
}

func TestCurrentAndAcknowledgmentStayWithTheirAccount(t *testing.T) {
	clock := newFakeClock(time.Now())
	clientContext := testClientContext()
	service := newTestService(t, clock, newScriptedFetcher(), func() ClientContext { return clientContext })
	message := testMessage("shared-campaign", clock.Now().Add(time.Hour))
	firstAccount := clientContext.UserID
	_, err := service.store.offer(firstAccount, clientContext.Locale, message, clock.Now())
	require.NoError(t, err)
	current, err := service.Current()
	require.NoError(t, err)
	require.Equal(t, firstAccount, current.AccountID)

	clientContext.UserID = "67890"
	current, err = service.Current()
	require.NoError(t, err)
	require.Nil(t, current)
	_, err = service.store.offer(clientContext.UserID, clientContext.Locale, message, clock.Now())
	require.NoError(t, err)
	require.ErrorIs(t, service.Acknowledge(message.DisplayID, firstAccount), ErrMessageNotPending)
	require.Empty(t, service.store.seen(clientContext.UserID))
	require.NoError(t, service.Acknowledge(message.DisplayID, clientContext.UserID))
	require.NoError(t, service.Acknowledge(message.DisplayID, clientContext.UserID))
}

func TestRefreshNotifiesWhenAccountHasNoMessage(t *testing.T) {
	clientContext := testClientContext()
	service := newTestService(t, newFakeClock(time.Now()), newScriptedFetcher(), func() ClientContext { return clientContext })
	changed := make(chan struct{}, 1)
	sub := events.Subscribe(func(AvailableEvent) { changed <- struct{}{} })
	t.Cleanup(sub.Unsubscribe)
	clientContext.UserID = "67890"
	service.Refresh()
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("account refresh did not invalidate presentation state")
	}
}

func TestServiceCancelsFetchAfterAccountReplacement(t *testing.T) {
	clock := newFakeClock(time.Now())
	fetcher := newScriptedFetcher()
	var mu sync.Mutex
	clientContext := testClientContext()
	provider := func() ClientContext {
		mu.Lock()
		defer mu.Unlock()
		return clientContext
	}
	service := newTestService(t, clock, fetcher, provider)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service.Start(ctx)

	require.Equal(t, "12345", receiveFetch(t, fetcher).clientContext.UserID)
	mu.Lock()
	clientContext.UserID = "67890"
	mu.Unlock()
	service.Refresh()

	require.Equal(t, "67890", receiveFetch(t, fetcher).clientContext.UserID)
	fetcher.results <- fetchResult{response: wire.UserMessageResponse{PollIntervalSeconds: 300}}
	receiveTimer(t, clock)
	require.Never(t, func() bool {
		select {
		case <-fetcher.requests:
			return true
		default:
			return false
		}
	}, 50*time.Millisecond, time.Millisecond)

	mu.Lock()
	clientContext.UserID = "12345"
	mu.Unlock()
	message, err := service.Current()
	require.NoError(t, err)
	require.Nil(t, message)
}

func TestServiceRechecksCredentialsWhenAccountEventIsMissed(t *testing.T) {
	clock := newFakeClock(time.Now())
	fetcher := newScriptedFetcher()
	var mu sync.Mutex
	clientContext := ClientContext{}
	provider := func() ClientContext {
		mu.Lock()
		defer mu.Unlock()
		return clientContext
	}
	service := newTestService(t, clock, fetcher, provider)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service.Start(ctx)

	require.Equal(t, 5*time.Minute, receiveTimer(t, clock))
	clock.Advance(5 * time.Minute)
	require.Equal(t, 5*time.Minute, receiveTimer(t, clock))
	require.Never(t, func() bool {
		select {
		case <-fetcher.requests:
			return true
		default:
			return false
		}
	}, 50*time.Millisecond, time.Millisecond)

	mu.Lock()
	clientContext = testClientContext()
	mu.Unlock()
	clock.Advance(5 * time.Minute)
	require.Equal(t, "12345", receiveFetch(t, fetcher).clientContext.UserID)
}

func TestServiceStillRefreshesImmediatelyWhenCredentialsBecomeAvailable(t *testing.T) {
	clock := newFakeClock(time.Now())
	fetcher := newScriptedFetcher()
	var mu sync.Mutex
	clientContext := ClientContext{}
	provider := func() ClientContext {
		mu.Lock()
		defer mu.Unlock()
		return clientContext
	}
	service := newTestService(t, clock, fetcher, provider)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service.Start(ctx)

	require.Equal(t, 5*time.Minute, receiveTimer(t, clock))
	mu.Lock()
	clientContext = testClientContext()
	mu.Unlock()
	service.Refresh()

	require.Equal(t, "12345", receiveFetch(t, fetcher).clientContext.UserID)
}

func TestServiceUsesLocalStateRetryWithoutAdvancingFetchBackoff(t *testing.T) {
	clock := newFakeClock(time.Now())
	fetcher := newScriptedFetcher()
	service := newTestService(t, clock, fetcher, func() ClientContext { return testClientContext() })
	service.store.path = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service.Start(ctx)

	receiveFetch(t, fetcher)
	fetcher.results <- fetchResult{response: wire.UserMessageResponse{
		PollIntervalSeconds: 60,
		Message:             testMessage("display-1", clock.Now().Add(time.Hour)),
	}}
	require.Equal(t, localStateRetryInterval, receiveTimer(t, clock))
	clock.Advance(localStateRetryInterval)

	receiveFetch(t, fetcher)
	fetcher.results <- fetchResult{err: errors.New("offline")}
	require.Equal(t, initialFailureBackoff, receiveTimer(t, clock))
}

func TestServiceLogsSafeFetchOutcomes(t *testing.T) {
	clock := newFakeClock(time.Now())
	fetcher := newScriptedFetcher()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	service, err := newService(Options{
		DataDir:         t.TempDir(),
		Fetcher:         fetcher,
		ContextProvider: func() ClientContext { return testClientContext() },
		Logger:          logger,
	}, dependencies{
		clock:  clock,
		jitter: func(delay time.Duration) time.Duration { return delay },
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service.Start(ctx)

	receiveFetch(t, fetcher)
	fetcher.results <- fetchResult{err: &httpStatusError{statusCode: http.StatusUnauthorized}}
	require.Equal(t, 5*time.Second, receiveTimer(t, clock))
	require.Contains(t, logs.String(), "category=authentication")
	require.Contains(t, logs.String(), "http_status=401")

	clock.Advance(5 * time.Second)
	receiveFetch(t, fetcher)
	fetcher.results <- fetchResult{response: wire.UserMessageResponse{
		PollIntervalSeconds: 300,
		Message:             testMessage("display-1", clock.Now().Add(time.Hour)),
	}}
	require.Equal(t, 5*time.Minute, receiveTimer(t, clock))
	require.Contains(t, logs.String(), "result=message_available")
	require.NotContains(t, logs.String(), "12345")
	require.NotContains(t, logs.String(), "secret-token")
	require.NotContains(t, logs.String(), "A safe localized message")
}

func TestServiceStopsAfterParentContextCancellation(t *testing.T) {
	clock := newFakeClock(time.Now())
	fetcher := newScriptedFetcher()
	service := newTestService(t, clock, fetcher, func() ClientContext { return testClientContext() })
	ctx, cancel := context.WithCancel(context.Background())
	service.Start(ctx)
	receiveFetch(t, fetcher)
	cancel()

	require.Never(t, func() bool {
		select {
		case <-fetcher.requests:
			return true
		default:
			return false
		}
	}, 50*time.Millisecond, time.Millisecond)
}

func TestContextNormalization(t *testing.T) {
	require.Equal(t, "macos", NormalizePlatform("darwin"))
	require.Equal(t, "windows", NormalizePlatform(" Windows "))
	require.Equal(t, "fa-IR", NormalizeLocale("fa-ir"))
	require.Equal(t, "en-US", NormalizeLocale("not a locale"))
}

func TestFailureJitterAndBackoffCap(t *testing.T) {
	for range 100 {
		delay := defaultJitter(5 * time.Minute)
		require.GreaterOrEqual(t, delay, 270*time.Second)
		require.LessOrEqual(t, delay, 5*time.Minute)
	}
	require.Equal(t, 5*time.Minute, failureBackoff(100))
}

func TestServiceRequiresDataDirectory(t *testing.T) {
	_, err := New(Options{
		Fetcher:         newScriptedFetcher(),
		ContextProvider: func() ClientContext { return testClientContext() },
	})
	require.EqualError(t, err, "user-message data directory is required")
}

type fetchCall struct {
	clientContext ClientContext
	seen          []string
}

type fetchResult struct {
	response wire.UserMessageResponse
	err      error
}

type scriptedFetcher struct {
	requests chan fetchCall
	results  chan fetchResult
}

func newScriptedFetcher() *scriptedFetcher {
	return &scriptedFetcher{
		requests: make(chan fetchCall, 8),
		results:  make(chan fetchResult, 8),
	}
}

func (f *scriptedFetcher) Fetch(
	ctx context.Context,
	clientContext ClientContext,
	seen []string,
) (wire.UserMessageResponse, error) {
	select {
	case f.requests <- fetchCall{clientContext: clientContext, seen: seen}:
	case <-ctx.Done():
		return wire.UserMessageResponse{}, ctx.Err()
	}
	select {
	case result := <-f.results:
		return result.response, result.err
	case <-ctx.Done():
		return wire.UserMessageResponse{}, ctx.Err()
	}
}

func newTestService(
	t *testing.T,
	clock clock,
	fetcher Fetcher,
	provider func() ClientContext,
) *Service {
	t.Helper()
	service, err := newService(Options{
		DataDir:         t.TempDir(),
		Fetcher:         fetcher,
		ContextProvider: provider,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, dependencies{
		clock:  clock,
		jitter: func(delay time.Duration) time.Duration { return delay },
	})
	require.NoError(t, err)
	return service
}

func receiveFetch(t *testing.T, fetcher *scriptedFetcher) fetchCall {
	t.Helper()
	select {
	case request := <-fetcher.requests:
		return request
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for fetch")
		return fetchCall{}
	}
}

func receiveTimer(t *testing.T, clock *fakeClock) time.Duration {
	t.Helper()
	select {
	case delay := <-clock.created:
		return delay
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for timer")
		return 0
	}
}

type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*fakeTimer
	created chan time.Duration
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now, created: make(chan time.Duration, 16)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(delay time.Duration) timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &fakeTimer{clock: c, due: c.now.Add(delay), ch: make(chan time.Time, 1)}
	c.timers = append(c.timers, timer)
	c.created <- delay
	return timer
}

func (c *fakeClock) Advance(delay time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delay)
	now := c.now
	for _, timer := range c.timers {
		if !timer.stopped && !timer.fired && !timer.due.After(now) {
			timer.fired = true
			timer.ch <- now
		}
	}
	c.mu.Unlock()
}

type fakeTimer struct {
	clock   *fakeClock
	due     time.Time
	ch      chan time.Time
	stopped bool
	fired   bool
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	wasActive := !t.stopped && !t.fired
	t.stopped = true
	return wasActive
}
