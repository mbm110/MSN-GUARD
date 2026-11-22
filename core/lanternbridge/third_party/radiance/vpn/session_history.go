package vpn

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/getlantern/radiance/events"
)

const (
	maxSessions      = 10
	sessionPollEvery = time.Second
	sessionRetention = 15 * time.Minute
	prunePeriod      = time.Minute
)

// Session covers a single server selection while connected. A new Session begins on connect and
// on every server switch; the prior Session is finalized at that boundary. History lives only in
// the daemon process — sessions are lost when the process exits.
type Session struct {
	ConnectedAt    time.Time     `json:"connected_at"`
	DisconnectedAt time.Time     `json:"disconnected_at,omitempty"`
	Server         SessionServer `json:"server"`
	BytesUp        int64         `json:"bytes_up"`
	BytesDown      int64         `json:"bytes_down"`
	Error          string        `json:"error,omitempty"`
}

type SessionServer struct {
	Tag     string `json:"tag,omitempty"`
	City    string `json:"city,omitempty"`
	Country string `json:"country,omitempty"`
}

// Duration returns the session length.
func (s Session) Duration() time.Duration {
	end := s.DisconnectedAt
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(s.ConnectedAt)
}

// SessionInfo supplies live session metadata to a SessionHistory. Bytes is invoked from a
// background poll goroutine, so the function must be safe for concurrent use.
type SessionInfo struct {
	Status         func() VPNStatus
	SelectedServer func() (tag, city, country string)
	Bytes          func() (up, down int64, ok bool)
}

// SessionHistory keeps an in-memory ring of recent VPN sessions, retaining the most recent
// maxSessions entries. A session covers a single server selection while connected; a server
// switch finalizes the current session and starts a new one.
type SessionHistory struct {
	logger    *slog.Logger
	info      SessionInfo
	sub       *events.Subscription[StatusUpdateEvent]
	closeOnce sync.Once

	// A tunnel restart resets the underlying traffic-manager counters mid-session; baseline
	// absorbs the prior tally so cumulative bytes stay monotonic across restarts.
	bytesMu        sync.Mutex
	startUp        int64
	startDown      int64
	baselineUp     int64
	baselineDown   int64
	livePolledUp   int64
	livePolledDown int64

	mu          sync.Mutex
	current     *Session
	stored      []Session
	pollCancel  context.CancelFunc
	pollDone    chan struct{}
	pruneCancel context.CancelFunc
	pruneDone   chan struct{}
}

// NewSessionHistory creates a SessionHistory subscribed to VPN status events. Call Close to
// unsubscribe and finalize any in-progress session.
func NewSessionHistory(logger *slog.Logger, info SessionInfo) *SessionHistory {
	if logger == nil {
		logger = slog.Default()
	}
	h := &SessionHistory{
		logger: logger,
		info:   info,
		// Preallocate the retention cap so finalizing a session can shift in place.
		stored: make([]Session, 0, maxSessions),
	}
	h.sub = events.Subscribe(h.handleStatus)
	h.startPruner()
	return h
}

// Close unsubscribes and finalizes any in-progress session. Safe to call multiple times.
func (h *SessionHistory) Close() {
	h.closeOnce.Do(func() {
		h.sub.Unsubscribe()
		h.stopPruner()
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.current != nil {
			h.finalizeLocked("")
		}
	})
}

func (h *SessionHistory) handleStatus(evt StatusUpdateEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Status events are dispatched in unordered goroutines, so reacting to intermediate statuses
	// risks a stale handler tearing down a session a concurrent Connected handler just started.
	// Gate on the live VPNClient status rather than the event payload.
	live := h.info.Status()
	switch evt.Status {
	case Connected:
		if live != Connected {
			return
		}
		// A Connected event arriving while a session is already active means the tunnel
		// re-attached after a restart; the existing session continues.
		if h.current != nil {
			return
		}
		tag, city, country := h.info.SelectedServer()
		h.startSessionLocked(tag, city, country)
	case Disconnected, ErrorStatus:
		if live == Connected || live == Restarting {
			return
		}
		h.finalizeLocked(evt.Error)
	}
}

// HandleServerChange finalizes the current per-server session and starts a new one for the new
// server. No-op when no session is active or when tag matches the current server.
func (h *SessionHistory) HandleServerChange(tag, city, country string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.current == nil {
		return
	}
	if h.current.Server.Tag == tag {
		return
	}
	h.finalizeLocked("")
	h.startSessionLocked(tag, city, country)
}

func (h *SessionHistory) startSessionLocked(tag, city, country string) {
	h.current = &Session{
		ConnectedAt: time.Now(),
		Server: SessionServer{
			Tag:     tag,
			City:    city,
			Country: country,
		},
	}
	h.snapshotStartBytesLocked()
	if h.pollCancel == nil {
		h.startPollLocked()
	}
}

func (h *SessionHistory) startPollLocked() {
	ctx, cancel := context.WithCancel(context.Background())
	h.pollCancel = cancel
	h.pollDone = make(chan struct{})
	go h.poll(ctx, h.pollDone)
}

func (h *SessionHistory) stopPollLocked() {
	if h.pollCancel == nil {
		return
	}
	h.pollCancel()
	<-h.pollDone
	h.pollCancel = nil
	h.pollDone = nil
}

func (h *SessionHistory) finalizeLocked(errMsg string) {
	if h.current == nil {
		return
	}
	h.stopPollLocked()
	h.sampleBytesLocked()
	now := time.Now()
	h.current.DisconnectedAt = now
	if errMsg != "" {
		h.current.Error = errMsg
	}
	s := *h.current
	h.current = nil
	// Avoid prepending onto a fresh slice while sessions may finalize under memory pressure.
	if len(h.stored) < maxSessions {
		h.stored = append(h.stored, Session{})
	}
	copy(h.stored[1:], h.stored[:len(h.stored)-1])
	h.stored[0] = s
	h.pruneLocked(now)
}

func (h *SessionHistory) pruneLocked(now time.Time) {
	cutoff := now.Add(-sessionRetention)
	for i, s := range h.stored {
		if s.DisconnectedAt.Before(cutoff) {
			h.stored = h.stored[:i]
			return
		}
	}
}

func (h *SessionHistory) startPruner() {
	ctx, cancel := context.WithCancel(context.Background())
	h.pruneCancel = cancel
	h.pruneDone = make(chan struct{})
	go h.prune(ctx, h.pruneDone)
}

func (h *SessionHistory) stopPruner() {
	if h.pruneCancel == nil {
		return
	}
	h.pruneCancel()
	<-h.pruneDone
	h.pruneCancel = nil
	h.pruneDone = nil
}

func (h *SessionHistory) prune(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(prunePeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			h.mu.Lock()
			h.pruneLocked(now)
			h.mu.Unlock()
		}
	}
}

func (h *SessionHistory) sampleBytesLocked() {
	if h.current == nil {
		return
	}
	if up, down, ok := h.info.Bytes(); ok {
		h.observeBytes(up, down)
	}
	h.current.BytesUp, h.current.BytesDown = h.sessionBytes()
}

func (h *SessionHistory) poll(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(sessionPollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if up, down, ok := h.info.Bytes(); ok {
				h.observeBytes(up, down)
			}
		}
	}
}

func (h *SessionHistory) observeBytes(up, down int64) {
	h.bytesMu.Lock()
	defer h.bytesMu.Unlock()
	// Decrease means the tunnel restarted and reset its counters; fold the prior tally forward.
	if up < h.livePolledUp {
		h.baselineUp += h.livePolledUp
	}
	if down < h.livePolledDown {
		h.baselineDown += h.livePolledDown
	}
	h.livePolledUp = up
	h.livePolledDown = down
}

func (h *SessionHistory) sessionBytes() (int64, int64) {
	h.bytesMu.Lock()
	defer h.bytesMu.Unlock()
	up := h.baselineUp + h.livePolledUp - h.startUp
	down := h.baselineDown + h.livePolledDown - h.startDown
	if up < 0 {
		up = 0
	}
	if down < 0 {
		down = 0
	}
	return up, down
}

func (h *SessionHistory) snapshotStartBytesLocked() {
	if up, down, ok := h.info.Bytes(); ok {
		h.observeBytes(up, down)
	}
	h.bytesMu.Lock()
	defer h.bytesMu.Unlock()
	h.startUp = h.baselineUp + h.livePolledUp
	h.startDown = h.baselineDown + h.livePolledDown
}

// Sessions returns recorded sessions in descending order (most recent first), including the
// current session if active. A limit value of 0 returns all sessions up to maxSessions.
func (h *SessionHistory) Sessions(limit int) []Session {
	h.mu.Lock()
	h.pruneLocked(time.Now())
	h.sampleBytesLocked()
	out := make([]Session, 0, len(h.stored)+1)
	if h.current != nil {
		out = append(out, *h.current)
	}
	out = append(out, h.stored...)
	h.mu.Unlock()
	if limit > 0 && limit < len(out) {
		out = out[:limit]
	}
	return out
}
