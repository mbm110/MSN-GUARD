package usermessage

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	wire "github.com/getlantern/common/usermessage"
	"github.com/getlantern/radiance/events"
)

const (
	initialFailureBackoff   = 5 * time.Second
	maxFailureBackoff       = 5 * time.Minute
	localStateRetryInterval = 5 * time.Minute
)

var errInvalidResponse = errors.New("invalid user-message response")

type clock interface {
	Now() time.Time
	NewTimer(time.Duration) timer
}

type timer interface {
	C() <-chan time.Time
	Stop() bool
}

type realClock struct{}

func (realClock) Now() time.Time                 { return time.Now() }
func (realClock) NewTimer(d time.Duration) timer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ *time.Timer }

func (t realTimer) C() <-chan time.Time { return t.Timer.C }

// Options configures a Service.
type Options struct {
	DataDir         string
	Fetcher         Fetcher
	ContextProvider func() ClientContext
	// Logger receives service diagnostics. New uses a service-scoped default
	// logger when Logger is nil.
	Logger *slog.Logger
}

type dependencies struct {
	clock  clock
	jitter func(time.Duration) time.Duration
}

// AvailableEvent signals that pending state may have changed without carrying its content.
type AvailableEvent struct {
	events.Event
}

// Message is a pending message scoped to its account for local presentation and acknowledgment.
type Message struct {
	wire.ResolvedUserMessage
	AccountID string `json:"account_id"`
}

// Service owns polling, per-account presentation state, and display acknowledgment.
type Service struct {
	fetcher         Fetcher
	contextProvider func() ClientContext
	clock           clock
	jitter          func(time.Duration) time.Duration
	logger          *slog.Logger
	store           *store
	wake            chan struct{}

	mu      sync.Mutex
	started bool
	active  bool
	// refreshGeneration lets us discard a response if a refresh arrived while it was in flight.
	refreshGeneration uint64
	requestCancel     context.CancelFunc
}

// New creates a user-message service and loads its durable state.
func New(opts Options) (*Service, error) {
	return newService(opts, dependencies{})
}

func newService(opts Options, deps dependencies) (*Service, error) {
	if opts.DataDir == "" {
		return nil, errors.New("user-message data directory is required")
	}
	if opts.Fetcher == nil {
		return nil, errors.New("user-message fetcher is required")
	}
	if opts.ContextProvider == nil {
		return nil, errors.New("user-message context provider is required")
	}
	state, err := newStore(opts.DataDir)
	if err != nil {
		return nil, err
	}
	if deps.clock == nil {
		deps.clock = realClock{}
	}
	if deps.jitter == nil {
		deps.jitter = defaultJitter
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default().With("service", "user_messages")
	}
	return &Service{
		fetcher:         opts.Fetcher,
		contextProvider: opts.ContextProvider,
		clock:           deps.clock,
		jitter:          deps.jitter,
		logger:          logger,
		store:           state,
		wake:            make(chan struct{}, 1),
		active:          true,
	}, nil
}

// Start begins with an immediate fetch and is idempotent.
func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()
	go s.run(ctx)
}

// Current returns the pending, unexpired message for the current account.
func (s *Service) Current() (*Message, error) {
	clientContext := s.contextProvider()
	if clientContext.UserID == "" {
		return nil, nil
	}
	message, err := s.store.current(clientContext.UserID, clientContext.Locale, s.clock.Now())
	if err != nil || message == nil {
		return nil, err
	}
	if s.contextProvider() != clientContext {
		return nil, nil
	}
	return &Message{ResolvedUserMessage: *message, AccountID: clientContext.UserID}, nil
}

// Refresh requests an immediate fetch. Concurrent requests are coalesced.
func (s *Service) Refresh() {
	s.mu.Lock()
	s.refreshGeneration++
	cancel := s.requestCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.signalRefresh()
	events.Emit(AvailableEvent{})
}

// signalRefresh coalesces pending wakeups.
func (s *Service) signalRefresh() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Acknowledge marks a pending message as displayed and refreshes eligibility.
func (s *Service) Acknowledge(displayID, accountID string) error {
	clientContext := s.contextProvider()
	if accountID == "" || accountID != clientContext.UserID {
		return ErrMessageNotPending
	}
	if err := s.store.acknowledge(clientContext.UserID, displayID, s.clock.Now()); err != nil {
		return err
	}
	s.Refresh()
	return nil
}

// SetActivity controls polling while the host app is active.
func (s *Service) SetActivity(active bool) {
	s.mu.Lock()
	changed := s.active != active
	s.active = active
	s.mu.Unlock()
	if changed {
		s.Refresh()
	}
}

// run owns the polling loop and keeps at most one fetch in flight.
func (s *Service) run(ctx context.Context) {
	var delay time.Duration
	var failures uint
	var credentialsDeferred bool
	for s.wait(ctx, delay) {
		requestContext, refreshGeneration, ok := s.beginRequest(ctx)
		if !ok {
			delay = 0
			continue
		}
		clientContext := s.contextProvider()
		if !clientContext.valid() {
			s.endRequest()
			failures = 0
			// Account changes wake us immediately; this bounds the wait if a local event is lost.
			delay = time.Duration(wire.MaxPollIntervalSeconds) * time.Second
			if !credentialsDeferred {
				s.logger.Debug("User-message fetch deferred", "reason", "credentials_unavailable")
				credentialsDeferred = true
			}
			continue
		}
		credentialsDeferred = false
		seen := s.store.seen(clientContext.UserID)
		response, err := s.fetcher.Fetch(requestContext, clientContext, seen)
		s.endRequest()
		if errors.Is(err, context.Canceled) {
			s.consumeRefresh()
			delay = 0
			continue
		}
		if err == nil {
			pollOnly := response
			pollOnly.Message = nil
			err = pollOnly.Validate()
			if err != nil {
				err = errInvalidResponse
			}
			if response.Message != nil && response.Message.Validate() != nil {
				s.logger.Warn("User-message response discarded", "category", "invalid_message")
				response.Message = nil
			}
		}
		if err != nil {
			failures++
			delay = s.jitter(failureBackoff(failures))
			s.logFetchFailure(err, failures, delay)
			continue
		}
		if s.refreshGenerationChanged(refreshGeneration) || s.contextProvider() != clientContext {
			s.consumeRefresh()
			delay = 0
			continue
		}
		changed, err := s.store.offer(clientContext.UserID, clientContext.Locale, response.Message, s.clock.Now())
		if err != nil {
			failures = 0
			delay = localStateRetryInterval
			s.logger.Warn(
				"User-message fetch result could not be persisted",
				"category", "local_state",
				"retry_in", delay,
			)
			continue
		}
		if changed {
			events.Emit(AvailableEvent{})
		}
		failures = 0
		delay = time.Duration(response.PollIntervalSeconds) * time.Second
		s.logFetchResult(response.Message, delay)
	}
}

func (s *Service) logFetchFailure(err error, failures uint, retryIn time.Duration) {
	category, statusCode := fetchFailureDetails(err)
	attributes := []any{
		"category", category,
		"failure_count", failures,
		"retry_in", retryIn,
	}
	if statusCode != 0 {
		attributes = append(attributes, "http_status", statusCode)
	}
	// Do not attach err here. Transport errors can contain request URLs, and
	// future error wrappers might include credentials or localized content.
	s.logger.Warn("User-message fetch failed", attributes...)
}

func fetchFailureDetails(err error) (category string, statusCode int) {
	if errors.Is(err, errInvalidResponse) {
		return "invalid_response", 0
	}
	if errors.Is(err, errCredentialsUnavailable) {
		return "credentials_unavailable", 0
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout", 0
	}
	var statusErr *httpStatusError
	if !errors.As(err, &statusErr) {
		return "transport", 0
	}
	statusCode = statusErr.statusCode
	switch {
	case statusCode == 400:
		category = "request_rejected"
	case statusCode == 401 || statusCode == 403:
		category = "authentication"
	case statusCode == 404:
		category = "endpoint"
	case statusCode == 408:
		category = "timeout"
	case statusCode == 429:
		category = "rate_limited"
	case statusCode >= 500:
		category = "server"
	default:
		category = "http"
	}
	return category, statusCode
}

func (s *Service) logFetchResult(message *wire.ResolvedUserMessage, pollIn time.Duration) {
	if message == nil {
		s.logger.Debug("User-message fetch completed", "result", "no_message", "poll_in", pollIn)
		return
	}
	s.logger.Info(
		"User-message fetch completed",
		"result", "message_available",
		"campaign_id", message.CampaignID,
		"revision_id", message.RevisionID,
		"delivery_id", message.DeliveryID,
		"surface", message.Surface,
		"locale", message.Locale,
		"expires_at", message.ExpiresAt,
		"poll_in", pollIn,
	)
}

// beginRequest reports whether polling is active and, when active, registers the current request.
func (s *Service) beginRequest(parent context.Context) (context.Context, uint64, bool) {
	requestContext, cancel := context.WithCancel(parent)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active {
		cancel()
		return nil, 0, false
	}
	s.requestCancel = cancel
	return requestContext, s.refreshGeneration, true
}

func (s *Service) endRequest() {
	s.mu.Lock()
	cancel := s.requestCancel
	s.requestCancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Service) refreshGenerationChanged(refreshGeneration uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshGeneration != refreshGeneration
}

// consumeRefresh drops a coalesced wake after its refresh has already been handled.
func (s *Service) consumeRefresh() {
	select {
	case <-s.wake:
	default:
	}
}

// wait reports whether polling may proceed. It returns false when ctx is canceled.
func (s *Service) wait(ctx context.Context, delay time.Duration) bool {
	for {
		if ctx.Err() != nil {
			return false
		}
		if !s.ready() {
			select {
			case <-ctx.Done():
				return false
			case <-s.wake:
				if s.ready() {
					return true
				}
				continue
			}
		}
		if delay <= 0 {
			return true
		}
		timer := s.clock.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-s.wake:
			timer.Stop()
			if s.ready() {
				return true
			}
			continue
		case <-timer.C():
			return true
		}
	}
}

func (s *Service) ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

func failureBackoff(failures uint) time.Duration {
	delay := initialFailureBackoff
	for i := uint(1); i < failures && delay < maxFailureBackoff; i++ {
		delay *= 2
		if delay >= maxFailureBackoff {
			return maxFailureBackoff
		}
	}
	return delay
}

func defaultJitter(delay time.Duration) time.Duration {
	if delay <= 0 {
		return 0
	}
	return time.Duration(float64(delay) * (0.9 + rand.Float64()*0.1))
}
