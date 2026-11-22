// Package helper fetches and renews this device's helper pairing tickets: the
// short-lived credentials lantern-cloud issues for each pairing the device is
// in, which put it in the pairing's room on freddie. A volunteer widget sends
// its volunteer tickets with every genesis message; an Unbounded consumer sends
// its inviter tickets when it subscribes.
//
// Tickets are credentials: nothing here logs them or a response body.
package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/getlantern/broflake/common/helperticket"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/sameorigin"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/traces"
)

const (
	// RefreshInterval is the longest a successful fetch is trusted before the
	// next is due. Tickets live 15 minutes, so readers always hold valid ones.
	RefreshInterval = 10 * time.Minute
	// RetryInterval is how long after a failed fetch the next is due. The
	// last tickets are kept meanwhile, until they expire.
	RetryInterval = time.Minute
	// DisabledInterval is how long after a 404, which means helper_invites is
	// off for this client, the next fetch is due.
	DisabledInterval = time.Hour

	// defaultLifetime is a ticket's life when neither the response nor the
	// ticket says.
	defaultLifetime = 15 * time.Minute
	maxLifetime     = 24 * time.Hour
	fetchTimeout    = 30 * time.Second
	maxBody         = 1 << 20
)

var (
	// ErrDisabled is Fetch's error when lantern-cloud has helper invites off
	// for this client.
	ErrDisabled = errors.New("helper invites are off for this client")
	// ErrUnavailable wraps Fetch's error when lantern-cloud asks the client to
	// back off (429 or 503).
	ErrUnavailable = errors.New("helper ticket service is busy")

	errPanicked = errors.New("ticket fetch panicked")
)

// Tickets are a device's pairing tickets, by role.
type Tickets struct {
	Inviter   []string
	Volunteer []string
	// Lifetime is how long lantern-cloud says the tickets live from now, or
	// 0 if it did not say.
	Lifetime time.Duration
	// InviterPairings maps the outbound tag of each pairing this device
	// invited to that pairing's ID, or is nil when lantern-cloud sent no tags.
	InviterPairings map[string]string
}

// Split sorts tickets by the role each claims. It does not verify them:
// freddie does.
func Split(tickets []string) Tickets {
	var t Tickets
	for _, tk := range tickets {
		switch role, _ := helperticket.Peek(tk); role {
		case helperticket.RoleInviter:
			t.Inviter = append(t.Inviter, tk)
		case helperticket.RoleVolunteer:
			t.Volunteer = append(t.Volunteer, tk)
		}
	}
	return t
}

// inviterPairings maps each tag in tags to the pairing of the inviter ticket
// at its index in tickets. tags must be index-aligned with tickets; a list of
// another length is ignored whole, since no ticket's tag can then be trusted.
func inviterPairings(tickets, tags []string) map[string]string {
	if len(tags) != len(tickets) {
		return nil
	}
	var m map[string]string
	for i, tag := range tags {
		if tag == "" {
			continue
		}
		role, pairing := helperticket.Peek(tickets[i])
		if role != helperticket.RoleInviter || pairing == "" {
			continue
		}
		if m == nil {
			m = make(map[string]string)
		}
		m[tag] = pairing
	}
	return m
}

// Fetcher asks lantern-cloud for this device's tickets.
type Fetcher struct {
	httpClient *http.Client
	baseURL    string
	usage      *Usage
}

// NewFetcher returns a Fetcher. baseURL includes the API version segment,
// as common.GetBaseURL() returns it. The Fetcher uses a copy of httpClient
// that follows redirects only within the request's origin, since a request
// body can carry pairing IDs.
func NewFetcher(httpClient *http.Client, baseURL string) *Fetcher {
	return &Fetcher{httpClient: sameorigin.Client(httpClient, "helper: tickets"), baseURL: baseURL}
}

// WithUsage makes every fetch report the bytes u has accumulated. A fetch
// that fails to send or gets a non-2xx response puts them back for the next,
// except on a 400, which drops them and fetches again without them.
func (f *Fetcher) WithUsage(u *Usage) *Fetcher {
	f.usage = u
	return f
}

type ticketRequest struct {
	PairedBytes []PairedBytes `json:"paired_bytes,omitempty"`
}

// Fetch calls POST {baseURL}/helper/tickets, authenticated by the device ID
// header like the peer API, and splits the tickets by role.
func (f *Fetcher) Fetch(ctx context.Context) (Tickets, error) {
	paired := f.usage.Take()
	delivered := false
	defer func() {
		if !delivered {
			f.usage.Restore(paired)
		}
	}()
	t, status, err := f.post(ctx, paired)
	if status == http.StatusBadRequest && len(paired) > 0 {
		// A server that predates paired_bytes rejects it, so the usage is
		// dropped rather than sent again.
		paired = nil
		t, status, err = f.post(ctx, nil)
	}
	delivered = status >= 200 && status < 300
	return t, err
}

// post sends one ticket request and returns the response status, 0 when none
// came back.
func (f *Fetcher) post(ctx context.Context, paired []PairedBytes) (Tickets, int, error) {
	payload, err := json.Marshal(ticketRequest{PairedBytes: paired})
	if err != nil {
		return Tickets{}, 0, fmt.Errorf("encode ticket request: %w", err)
	}
	// Untraced also keeps a redirect off /helper/ out of traces.
	r, err := common.NewRequestWithHeaders(traces.Untraced(ctx), http.MethodPost, f.baseURL+"/helper/tickets", bytes.NewReader(payload))
	if err != nil {
		return Tickets{}, 0, fmt.Errorf("build ticket request: %w", err)
	}
	r.Header.Set("Content-Type", "application/json")
	if val := settings.GetString(settings.FeatureOverridesKey); val != "" {
		r.Header.Set("X-Lantern-Feature-Override", val)
	}
	resp, err := f.httpClient.Do(r)
	if err != nil {
		return Tickets{}, 0, fmt.Errorf("send ticket request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	status := resp.StatusCode
	switch {
	case status == http.StatusNotFound:
		return Tickets{}, status, ErrDisabled
	case status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable:
		return Tickets{}, status, fmt.Errorf("ticket request: status %d: %w", status, ErrUnavailable)
	case status < 200 || status >= 300:
		return Tickets{}, status, fmt.Errorf("ticket request: status %d", status)
	}
	var body struct {
		Tickets         []string `json:"tickets"`
		InviterTags     []string `json:"inviter_tags"`
		LifetimeSeconds int64    `json:"lifetime_seconds"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&body); err != nil {
		return Tickets{}, status, errors.New("ticket response: malformed JSON")
	}
	t := Split(body.Tickets)
	t.InviterPairings = inviterPairings(body.Tickets, body.InviterTags)
	if body.LifetimeSeconds > 0 && body.LifetimeSeconds <= int64(maxLifetime/time.Second) {
		t.Lifetime = time.Duration(body.LifetimeSeconds) * time.Second
	}
	return t, status, nil
}

// held is a ticket and when this device stops serving it.
type held struct {
	ticket  string
	expires time.Time
}

// Source keeps a device's tickets fresh for code that reads them on its
// signaling path. A read never blocks: it returns the unexpired tickets the
// last successful fetch got, and when a fetch is due it starts one in the
// background. Nothing is fetched until the first read, so a device that never
// reads never calls the API. Source is safe for concurrent use.
type Source struct {
	ctx   context.Context
	fetch func(context.Context) (Tickets, error)
	now   func() time.Time

	mu        sync.Mutex
	inviter   []held
	volunteer []held
	// pairings is the last answered fetch's Tickets.InviterPairings.
	pairings map[string]string
	// answered is set once lantern-cloud has answered a fetch, with tickets
	// or with ErrDisabled.
	answered bool
	onChange func()
	// afterRead, if set, runs after read releases s.mu. For tests.
	afterRead func()
	due       time.Time // zero: due at the first read
	// fetched is closed once a fetch has finished, whatever its outcome. Made on first use.
	fetched     chan struct{}
	everFetched bool
	fetching    bool
	busy        time.Duration // the backoff after the last 429 or 503 in a row
	gen         uint64        // bumped by Invalidate; a fetch started under an older gen is stale
}

// NewSource returns a Source that fetches with fetch, Fetcher.Fetch outside
// tests. Cancelling ctx cancels a fetch in flight and stops further fetches.
func NewSource(ctx context.Context, fetch func(context.Context) (Tickets, error)) *Source {
	return &Source{ctx: ctx, fetch: fetch, now: time.Now}
}

// WaitFetched starts a fetch if one is due and waits until a fetch has
// finished, whatever its outcome, or ctx is done. It reports whether one has.
// Reads never block, so a caller that must not act on "no tickets" before
// lantern-cloud has had a chance to answer waits here first, with a deadline.
func (s *Source) WaitFetched(ctx context.Context) bool {
	s.mu.Lock()
	s.readLocked(helperticket.RoleVolunteer, false)
	ch := s.fetchedLocked()
	s.mu.Unlock()
	select {
	case <-ch:
		return true
	case <-ctx.Done():
		return false
	}
}

// fetchedLocked returns the channel closed once a fetch has finished.
func (s *Source) fetchedLocked() chan struct{} {
	if s.fetched == nil {
		s.fetched = make(chan struct{})
	}
	return s.fetched
}

// Inviter returns the current inviter tickets.
func (s *Source) Inviter() []string {
	return s.read(helperticket.RoleInviter, false)
}

// InviterFor returns the current inviter tickets for the pairing whose
// outbound tag is tag, and whether lantern-cloud has answered a fetch yet:
// until it has, no tickets means only that none are known.
func (s *Source) InviterFor(tag string) (tickets []string, answered bool) {
	all, pairings, answered := s.inviterSnapshot()
	pairing, ok := pairings[tag]
	if !ok {
		return nil, answered
	}
	for _, tk := range all {
		if _, p := helperticket.Peek(tk); p == pairing {
			tickets = append(tickets, tk)
		}
	}
	return tickets, answered
}

// InviterTags returns the outbound tags of the pairings this device invited
// that have a current inviter ticket, sorted.
func (s *Source) InviterTags() []string {
	all, pairings, _ := s.inviterSnapshot()
	held := make(map[string]bool, len(all))
	for _, tk := range all {
		_, p := helperticket.Peek(tk)
		held[p] = true
	}
	var tags []string
	for tag, pairing := range pairings {
		if held[pairing] {
			tags = append(tags, tag)
		}
	}
	slices.Sort(tags)
	return tags
}

// usableTagsLocked returns the tags in s.pairings whose pairing has an inviter
// ticket unexpired at now. The caller must hold s.mu.
func (s *Source) usableTagsLocked(now time.Time) map[string]bool {
	held := make(map[string]bool, len(s.inviter))
	for _, h := range s.inviter {
		if now.Before(h.expires) {
			_, p := helperticket.Peek(h.ticket)
			held[p] = true
		}
	}
	usable := make(map[string]bool, len(s.pairings))
	for tag, pairing := range s.pairings {
		if held[pairing] {
			usable[tag] = true
		}
	}
	return usable
}

// inviterSnapshot reads the current inviter tickets, starting a fetch if one
// is due, together with the pairings and answered state they came with. The
// map must not be modified.
func (s *Source) inviterSnapshot() (tickets []string, pairings map[string]string, answered bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readLocked(helperticket.RoleInviter, false), s.pairings, s.answered
}

// SetOnInviterChange sets f to run after a fetch first answers, or changes the
// inviter pairings InviterFor knows or which of them have an unexpired
// ticket. f runs on the fetch's goroutine, with no lock held.
func (s *Source) SetOnInviterChange(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = f
}

// Volunteer returns the current volunteer tickets.
func (s *Source) Volunteer() []string {
	return s.read(helperticket.RoleVolunteer, false)
}

// AnsweredVolunteer returns the volunteer tickets from the last fetch
// lantern-cloud answered, expired ones included: nil after it said helper
// invites are off, and unchanged while fetches fail. A pairing missing from it
// has ended; one missing only from Volunteer may just have lapsed while
// lantern-cloud was unreachable. It never goes on the wire.
func (s *Source) AnsweredVolunteer() []string {
	return s.read(helperticket.RoleVolunteer, true)
}

// Invalidate makes the next read fetch, because this device's pairings have
// changed: it ends a DisabledInterval wait, whose 404 a claim makes stale. A
// fetch already in flight does not satisfy it (see gen). A Source backing off
// after lantern-cloud said it was busy keeps its backoff.
func (s *Source) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gen++
	if s.busy == 0 {
		s.due = time.Time{}
	}
}

func (s *Source) read(role helperticket.Role, expired bool) []string {
	s.mu.Lock()
	out := s.readLocked(role, expired)
	s.mu.Unlock()
	if s.afterRead != nil {
		s.afterRead()
	}
	return out
}

// readLocked is read for a caller holding s.mu.
func (s *Source) readLocked(role helperticket.Role, expired bool) []string {
	now := s.now()
	if !s.fetching && !now.Before(s.due) && s.ctx.Err() == nil {
		s.fetching = true
		go s.refresh(s.gen)
	}
	hs := s.volunteer
	if role == helperticket.RoleInviter {
		hs = s.inviter
	}
	var out []string
	for _, h := range hs {
		if expired || now.Before(h.expires) {
			out = append(out, h.ticket)
		}
	}
	return out
}

func (s *Source) refresh(gen uint64) {
	// Expiry runs from when the request was sent, so latency never stretches
	// a ticket's life past what lantern-cloud granted.
	start := s.now()
	t, err := s.safeFetch()
	// Before taking the lock, so the logged duration is the fetch's alone.
	took := s.now().Sub(start)
	s.mu.Lock()
	now := s.now()
	s.fetching = false
	if !s.everFetched {
		s.everFetched = true
		close(s.fetchedLocked())
	}
	prevPairings, prevAnswered, prevUsable := s.pairings, s.answered, s.usableTagsLocked(now)
	switch {
	case errors.Is(err, ErrDisabled):
		s.inviter, s.volunteer = nil, nil
		s.pairings, s.answered = nil, true
		s.busy = 0
		s.due = now.Add(DisabledInterval)
	case errors.Is(err, ErrUnavailable):
		s.busy = min(max(2*s.busy, 2*RetryInterval), RefreshInterval)
		s.due = now.Add(s.busy)
	case err != nil:
		s.busy = 0
		s.due = now.Add(RetryInterval)
	default:
		s.inviter = hold(t.Inviter, start, t.Lifetime)
		s.volunteer = hold(t.Volunteer, start, t.Lifetime)
		s.pairings, s.answered = t.InviterPairings, true
		s.busy = 0
		// Renewal runs from the request's start too, like expiry, so a
		// slow fetch never eats into the margin before the tickets expire.
		s.due = start.Add(refreshAfter(t.Lifetime))
	}
	if s.gen != gen && s.busy == 0 {
		// The pairings changed while this fetch was in flight, so whatever it
		// got (tickets, a 404 for a device not yet paired, an error) may
		// predate the change: fetch again at the next read. A busy backoff
		// stands.
		s.due = time.Time{}
	}
	var onChange func()
	if s.answered != prevAnswered || !maps.Equal(s.pairings, prevPairings) ||
		!maps.Equal(s.usableTagsLocked(now), prevUsable) {
		onChange = s.onChange
	}
	s.mu.Unlock()
	if onChange != nil {
		onChange()
	}

	// How long a fetch takes bounds how soon a rooms consumer on a cold start can subscribe with
	// its tickets.
	switch {
	case errors.Is(err, errPanicked):
		slog.Warn("helper: fetching pairing tickets panicked", "took", took)
	case errors.Is(err, ErrDisabled):
		slog.Debug("helper: lantern-cloud has helper invites off for this client", "took", took)
	case err != nil:
		slog.Debug("helper: fetching pairing tickets failed; keeping the last ones", "error", err, "took", took)
	case err == nil:
		slog.Debug("helper: fetched pairing tickets", "took", took, "inviter", len(t.Inviter), "volunteer", len(t.Volunteer))
	}
}

// safeFetch calls fetch, turning a panic into errPanicked.
func (s *Source) safeFetch() (t Tickets, err error) {
	defer func() {
		if recover() != nil {
			t, err = Tickets{}, errPanicked
		}
	}()
	ctx, cancel := context.WithTimeout(s.ctx, fetchTimeout)
	defer cancel()
	return s.fetch(ctx)
}

// hold stamps tickets fetched at fetchedAt with their expiry. The response's
// lifetime comes first because it is measured on this device's clock, which
// may be skewed from the server's; the ticket's own claim is the fallback.
func hold(tickets []string, fetchedAt time.Time, lifetime time.Duration) []held {
	out := make([]held, 0, len(tickets))
	for _, tk := range tickets {
		exp := fetchedAt.Add(defaultLifetime)
		if lifetime > 0 {
			exp = fetchedAt.Add(lifetime)
		} else if c, ok := helperticket.Claims(tk); ok {
			exp = c.Expires
		}
		out = append(out, held{ticket: tk, expires: exp})
	}
	return out
}

// refreshAfter is how long after a successful fetch the next is due: two
// thirds of the tickets' life, at most RefreshInterval and at least
// RetryInterval.
func refreshAfter(lifetime time.Duration) time.Duration {
	if lifetime <= 0 {
		return RefreshInterval
	}
	return max(min(RefreshInterval, lifetime*2/3), RetryInterval)
}

// isFetching reports whether a fetch is in flight. For tests.
func (s *Source) isFetching() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetching
}
