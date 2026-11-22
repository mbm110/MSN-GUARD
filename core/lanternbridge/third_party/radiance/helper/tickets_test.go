package helper

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getlantern/broflake/common/helperticket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/traces"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "radiance-helper-settings-*")
	if err != nil {
		panic(err)
	}
	if err := settings.InitSettings(dir); err != nil {
		os.RemoveAll(dir)
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// testTickets returns an inviter and a volunteer ticket for one pairing.
func testTickets(t *testing.T) (inviter, volunteer string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	sign := func(role helperticket.Role) string {
		tk, err := helperticket.Sign(priv, helperticket.Ticket{
			PairingID: "6f1c2b0e-8a7d-4c1e-9f00-0123456789ab", Role: role, Expires: time.Now().Add(15 * time.Minute)})
		require.NoError(t, err)
		return tk
	}
	return sign(helperticket.RoleInviter), sign(helperticket.RoleVolunteer)
}

func TestFetcherSplitsTicketsByRole(t *testing.T) {
	inv, vol := testTickets(t)
	require.NoError(t, settings.Set(settings.DeviceIDKey, "device-A"))
	var method, path, device string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path, device = r.Method, r.URL.Path, r.Header.Get(common.DeviceIDHeader)
		json.NewEncoder(w).Encode(map[string]any{"tickets": []string{vol, inv, "junk"}, "lifetime_seconds": 900})
	}))
	defer srv.Close()

	got, err := NewFetcher(srv.Client(), srv.URL+"/v1").Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, method)
	assert.Equal(t, "/v1/helper/tickets", path)
	assert.Equal(t, "device-A", device)
	assert.Equal(t, Tickets{Inviter: []string{inv}, Volunteer: []string{vol}, Lifetime: 900 * time.Second}, got)
}

func TestFetcherNotFoundMeansDisabled(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	_, err := NewFetcher(srv.Client(), srv.URL+"/v1").Fetch(context.Background())
	assert.ErrorIs(t, err, ErrDisabled)
}

// The response body is tickets, so an error never quotes it.
func TestFetcherErrorOmitsTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("eyJzZWNyZXQi.c2ln"))
	}))
	defer srv.Close()
	_, err := NewFetcher(srv.Client(), srv.URL+"/v1").Fetch(context.Background())
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "eyJzZWNyZXQi")
}

// fakeFetch hands out results the test sends, and counts calls.
type fakeFetch struct {
	calls   atomic.Int32
	results chan fetchResult
}

type fetchResult struct {
	t   Tickets
	err error
}

func (f *fakeFetch) fetch(ctx context.Context) (Tickets, error) {
	f.calls.Add(1)
	r := <-f.results
	return r.t, r.err
}

// fakeClock is a settable now.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestSourceRefreshesOnRead(t *testing.T) {
	inv, vol := testTickets(t)
	f := &fakeFetch{results: make(chan fetchResult)}
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	src := NewSource(context.Background(), f.fetch)
	src.now = clock.now

	assert.Empty(t, src.Inviter(), "the first read starts a fetch and does not wait for it")
	require.Eventually(t, func() bool { return f.calls.Load() == 1 }, time.Second, time.Millisecond)
	f.results <- fetchResult{t: Tickets{Inviter: []string{inv}, Volunteer: []string{vol}, Lifetime: 15 * time.Minute}}
	require.Eventually(t, func() bool { return len(src.Inviter()) == 1 }, time.Second, time.Millisecond)
	assert.Equal(t, []string{vol}, src.Volunteer())

	clock.add(RefreshInterval - time.Second)
	src.Inviter()
	assert.Never(t, func() bool { return f.calls.Load() > 1 }, 50*time.Millisecond, time.Millisecond, "fetched before the refresh was due")

	clock.add(time.Second)
	src.Volunteer()
	require.Eventually(t, func() bool { return f.calls.Load() == 2 }, time.Second, time.Millisecond)
	f.results <- fetchResult{err: errors.New("network down")}
	require.Eventually(t, func() bool { return !src.isFetching() }, time.Second, time.Millisecond)
	assert.Equal(t, []string{inv}, src.Inviter(), "a failed fetch keeps the last tickets")

	clock.add(RetryInterval)
	src.Inviter()
	require.Eventually(t, func() bool { return f.calls.Load() == 3 }, time.Second, time.Millisecond)
	f.results <- fetchResult{err: ErrDisabled}
	require.Eventually(t, func() bool { return len(src.Inviter()) == 0 }, time.Second, time.Millisecond)
	assert.Empty(t, src.Volunteer(), "helper_invites off clears the tickets")

	clock.add(DisabledInterval - time.Second)
	src.Inviter()
	assert.Never(t, func() bool { return f.calls.Load() > 3 }, 50*time.Millisecond, time.Millisecond, "fetched before the disabled backoff ended")
	clock.add(time.Second)
	src.Inviter()
	require.Eventually(t, func() bool { return f.calls.Load() == 4 }, time.Second, time.Millisecond)
	f.results <- fetchResult{}
}

func TestSourceReturnsCopies(t *testing.T) {
	inv, _ := testTickets(t)
	f := &fakeFetch{results: make(chan fetchResult, 1)}
	f.results <- fetchResult{t: Tickets{Inviter: []string{inv}}}
	src := NewSource(context.Background(), f.fetch)
	src.Inviter()
	require.Eventually(t, func() bool { return len(src.Inviter()) == 1 }, time.Second, time.Millisecond)
	got := src.Inviter()
	got[0] = "changed"
	assert.Equal(t, []string{inv}, src.Inviter())
}

func TestFetcherSendsFeatureOverride(t *testing.T) {
	require.NoError(t, settings.Set(settings.FeatureOverridesKey, "helper_invites"))
	t.Cleanup(func() { _ = settings.Set(settings.FeatureOverridesKey, "") })
	var override string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		override = r.Header.Get("X-Lantern-Feature-Override")
		w.Write([]byte(`{"tickets":[]}`))
	}))
	defer srv.Close()
	_, err := NewFetcher(srv.Client(), srv.URL+"/v1").Fetch(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "helper_invites", override)
}

func TestFetcherBusyStatusesAreUnavailable(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
		_, err := NewFetcher(srv.Client(), srv.URL+"/v1").Fetch(context.Background())
		srv.Close()
		assert.ErrorIs(t, err, ErrUnavailable, "status %d", code)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer srv.Close()
	_, err := NewFetcher(srv.Client(), srv.URL+"/v1").Fetch(context.Background())
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrUnavailable)
}

// newTestSource returns a Source on a fake clock, fetching from f.
func newTestSource(f *fakeFetch) (*Source, *fakeClock) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	src := NewSource(context.Background(), f.fetch)
	src.now = clock.now
	return src, clock
}

// settle waits for the fetch in flight to finish.
func settle(t *testing.T, src *Source) {
	t.Helper()
	require.Eventually(t, func() bool { return !src.isFetching() }, time.Second, time.Millisecond)
}

// awaitChanges waits until count reaches want: a fetch ends before its change
// callback runs, so settle alone does not wait for the callback.
func awaitChanges(t *testing.T, count func() int, want int, msg ...any) {
	t.Helper()
	require.Eventually(t, func() bool { return count() >= want }, time.Second, time.Millisecond, msg...)
	assert.Equal(t, want, count(), msg...)
}

// assertNoChange gives a callback the fetch that just settled might run time
// to arrive, then asserts count is still want.
func assertNoChange(t *testing.T, count func() int, want int, msg ...any) {
	t.Helper()
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, want, count(), msg...)
}

func (s *Source) dueIn() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.due.Sub(s.now())
}

func TestSourceDropsExpiredTickets(t *testing.T) {
	inv, vol := testTickets(t)
	f := &fakeFetch{results: make(chan fetchResult, 1)}
	src, clock := newTestSource(f)

	f.results <- fetchResult{t: Tickets{Inviter: []string{inv}, Volunteer: []string{vol}, Lifetime: 15 * time.Minute}}
	src.Inviter()
	settle(t, src)
	require.Equal(t, []string{inv}, src.Inviter())

	clock.add(RefreshInterval)
	for i := 0; i < 4; i++ {
		f.results <- fetchResult{err: errors.New("network down")}
		src.Inviter()
		settle(t, src)
		clock.add(RetryInterval)
	}
	// 14 minutes after the fetch: still valid.
	f.results <- fetchResult{err: errors.New("network down")}
	assert.Equal(t, []string{inv}, src.Inviter())
	settle(t, src)
	clock.add(time.Minute)
	f.results <- fetchResult{err: errors.New("network down")}
	assert.Empty(t, src.Inviter(), "an expired ticket is never served")
	assert.Empty(t, src.Volunteer(), "an expired ticket is never served")
	settle(t, src)
}

func TestSourceExpiryFallsBackToTheClaim(t *testing.T) {
	inv, _ := testTickets(t) // claims expiry at real now + 15m
	f := &fakeFetch{results: make(chan fetchResult, 1)}
	src := NewSource(context.Background(), f.fetch)
	clock := &fakeClock{t: time.Now()}
	src.now = clock.now
	f.results <- fetchResult{t: Tickets{Inviter: []string{inv}}}
	src.Inviter()
	settle(t, src)
	assert.Equal(t, []string{inv}, src.Inviter())
	clock.add(15*time.Minute + time.Second)
	f.results <- fetchResult{err: errors.New("network down")}
	assert.Empty(t, src.Inviter())
	settle(t, src)
}

func TestSourceRecoversFromAPanickingFetch(t *testing.T) {
	var calls atomic.Int32
	src := NewSource(context.Background(), func(context.Context) (Tickets, error) {
		calls.Add(1)
		panic("boom")
	})
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	src.now = clock.now
	src.Inviter()
	settle(t, src)
	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, RetryInterval, src.dueIn())
	clock.add(RetryInterval)
	src.Inviter()
	settle(t, src)
	assert.Equal(t, int32(2), calls.Load(), "a panic does not stop later fetches")
}

func TestSourceBacksOffWhileBusy(t *testing.T) {
	f := &fakeFetch{results: make(chan fetchResult, 1)}
	src, clock := newTestSource(f)
	step := func(r fetchResult) time.Duration {
		f.results <- r
		src.Inviter()
		settle(t, src)
		d := src.dueIn()
		clock.add(d)
		return d
	}
	busy := fetchResult{err: fmt.Errorf("ticket request: status 429: %w", ErrUnavailable)}
	assert.Equal(t, 2*time.Minute, step(busy))
	assert.Equal(t, 4*time.Minute, step(busy))
	assert.Equal(t, 8*time.Minute, step(busy))
	assert.Equal(t, RefreshInterval, step(busy))
	assert.Equal(t, RefreshInterval, step(busy))
	assert.Equal(t, RetryInterval, step(fetchResult{err: errors.New("network down")}), "an ordinary failure ends the streak")
	assert.Equal(t, 2*time.Minute, step(busy))
	assert.Equal(t, RefreshInterval, step(fetchResult{t: Tickets{Lifetime: 15 * time.Minute}}))
	assert.Equal(t, 2*time.Minute, step(busy), "a success resets the backoff")
}

func TestSourceRefreshFollowsTheLifetime(t *testing.T) {
	f := &fakeFetch{results: make(chan fetchResult, 1)}
	src, _ := newTestSource(f)
	f.results <- fetchResult{t: Tickets{Lifetime: 6 * time.Minute}}
	src.Inviter()
	settle(t, src)
	assert.Equal(t, 4*time.Minute, src.dueIn())
}

func TestSourceFetchesOncePerDuePeriod(t *testing.T) {
	inv, _ := testTickets(t)
	f := &fakeFetch{results: make(chan fetchResult)}
	src, clock := newTestSource(f)
	readAll := func() {
		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				src.Inviter()
				src.Volunteer()
			}()
		}
		wg.Wait()
	}
	readAll()
	require.Eventually(t, func() bool { return f.calls.Load() == 1 }, time.Second, time.Millisecond)
	readAll()
	f.results <- fetchResult{t: Tickets{Inviter: []string{inv}, Lifetime: 15 * time.Minute}}
	settle(t, src)
	readAll()
	assert.Never(t, func() bool { return f.calls.Load() > 1 }, 50*time.Millisecond, time.Millisecond)
	clock.add(RefreshInterval)
	readAll()
	require.Eventually(t, func() bool { return f.calls.Load() == 2 }, time.Second, time.Millisecond)
	assert.Never(t, func() bool { return f.calls.Load() > 2 }, 50*time.Millisecond, time.Millisecond)
	f.results <- fetchResult{}
	settle(t, src)
}

func TestSourceCancelsFetchWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var calls atomic.Int32
	src := NewSource(ctx, func(fctx context.Context) (Tickets, error) {
		calls.Add(1)
		close(started)
		<-fctx.Done()
		return Tickets{}, fctx.Err()
	})
	src.Inviter()
	<-started
	cancel()
	settle(t, src)
	src.now = func() time.Time { return time.Now().Add(time.Hour) }
	src.Inviter()
	assert.Never(t, func() bool { return calls.Load() > 1 }, 50*time.Millisecond, time.Millisecond, "a cancelled Source never fetches again")
}

// Expiry runs from when the request was sent, so a slow response does not
// stretch a ticket's life.
func TestSourceExpiryRunsFromTheRequest(t *testing.T) {
	inv, _ := testTickets(t)
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	start := clock.now()
	var calls atomic.Int32
	src := NewSource(context.Background(), func(context.Context) (Tickets, error) {
		if calls.Add(1) == 1 {
			clock.add(20 * time.Second)
			return Tickets{Inviter: []string{inv}, Lifetime: 15 * time.Minute}, nil
		}
		return Tickets{}, errors.New("network down")
	})
	src.now = clock.now
	src.Inviter()
	settle(t, src)
	clock.add(start.Add(15*time.Minute - time.Second).Sub(clock.now()))
	assert.Equal(t, []string{inv}, src.Inviter())
	settle(t, src)
	clock.add(start.Add(15 * time.Minute).Sub(clock.now()))
	assert.Empty(t, src.Inviter(), "expired 15 minutes after the request, not the response")
	settle(t, src)
}

// Renewal also runs from when the request was sent, so a slow response does
// not eat into the margin before the tickets expire.
func TestSourceRenewalRunsFromTheRequest(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	src := NewSource(context.Background(), func(context.Context) (Tickets, error) {
		clock.add(25 * time.Second)
		return Tickets{Lifetime: 6 * time.Minute}, nil
	})
	src.now = clock.now
	src.Inviter()
	settle(t, src)
	assert.Equal(t, 4*time.Minute-25*time.Second, src.dueIn())
}

// AnsweredVolunteer keeps what lantern-cloud last answered, expired or not,
// until a fetch answers again; a 404 clears it.
func TestSourceAnsweredVolunteerOutlivesExpiry(t *testing.T) {
	_, vol := testTickets(t)
	f := &fakeFetch{results: make(chan fetchResult, 1)}
	src, clock := newTestSource(f)
	f.results <- fetchResult{t: Tickets{Volunteer: []string{vol}, Lifetime: 15 * time.Minute}}
	src.Volunteer()
	settle(t, src)
	clock.add(20 * time.Minute)
	f.results <- fetchResult{err: errors.New("network down")}
	assert.Empty(t, src.Volunteer(), "expired tickets leave the wire")
	settle(t, src)
	assert.Equal(t, []string{vol}, src.AnsweredVolunteer(), "a failed fetch ends no pairing")
	clock.add(RetryInterval)
	f.results <- fetchResult{err: ErrDisabled}
	src.AnsweredVolunteer()
	settle(t, src)
	assert.Empty(t, src.AnsweredVolunteer(), "a 404 does")
}

func TestSourceInvalidate(t *testing.T) {
	var fetches atomic.Int32
	src := NewSource(context.Background(), func(context.Context) (Tickets, error) {
		fetches.Add(1)
		return Tickets{Lifetime: 15 * time.Minute}, nil
	})
	src.Volunteer()
	require.Eventually(t, func() bool { return !src.isFetching() && fetches.Load() == 1 }, time.Second, 5*time.Millisecond)
	src.Volunteer()
	assert.Never(t, func() bool { return fetches.Load() > 1 }, 30*time.Millisecond, time.Millisecond, "a fresh source does not refetch")
	src.Invalidate()
	src.Volunteer()
	require.Eventually(t, func() bool { return !src.isFetching() && fetches.Load() == 2 }, time.Second, 5*time.Millisecond)
}

// TestSourceInvalidateDuringAFetchIsNotLost covers the race: a pairing that
// changes while a fetch is in flight must not be hidden by that fetch's
// success, whose tickets may predate the change.
func TestSourceInvalidateDuringAFetchIsNotLost(t *testing.T) {
	release := make(chan struct{})
	var fetches atomic.Int32
	src := NewSource(context.Background(), func(context.Context) (Tickets, error) {
		if fetches.Add(1) == 1 {
			<-release
		}
		return Tickets{Lifetime: 15 * time.Minute}, nil
	})
	src.Volunteer()
	require.Eventually(t, func() bool { return fetches.Load() == 1 }, time.Second, 5*time.Millisecond)
	src.Invalidate()
	close(release)
	require.Eventually(t, func() bool { return !src.isFetching() }, time.Second, 5*time.Millisecond)
	src.Volunteer()
	require.Eventually(t, func() bool { return fetches.Load() == 2 }, time.Second, 5*time.Millisecond,
		"the fetch that began before the change does not count as fresh")
}

// TestSourceInvalidateDuringADisabledFetchIsNotLost: a flag-off volunteer's
// fetch answers 404 (ErrDisabled) until its pairing exists. An approval that
// lands during that fetch must not wait out DisabledInterval.
func TestSourceInvalidateDuringADisabledFetchIsNotLost(t *testing.T) {
	release := make(chan struct{})
	var fetches atomic.Int32
	src := NewSource(context.Background(), func(context.Context) (Tickets, error) {
		if fetches.Add(1) == 1 {
			<-release
			return Tickets{}, ErrDisabled
		}
		return Tickets{Lifetime: 15 * time.Minute}, nil
	})
	src.Volunteer()
	require.Eventually(t, func() bool { return fetches.Load() == 1 }, time.Second, 5*time.Millisecond)
	src.Invalidate()
	close(release)
	require.Eventually(t, func() bool { return !src.isFetching() }, time.Second, 5*time.Millisecond)
	src.Volunteer()
	require.Eventually(t, func() bool { return fetches.Load() == 2 }, time.Second, 5*time.Millisecond,
		"the 404 that raced the approval does not hold the next fetch for an hour")
}

// A 404 that already settled holds the next fetch for DisabledInterval; a
// claim that succeeds after it makes that 404 stale, so Invalidate ends the
// wait, and the tickets it then gets replace the cleared AnsweredVolunteer.
func TestSourceInvalidateEndsTheDisabledWait(t *testing.T) {
	_, vol := testTickets(t)
	f := &fakeFetch{results: make(chan fetchResult, 1)}
	src, _ := newTestSource(f)
	f.results <- fetchResult{err: ErrDisabled}
	src.Volunteer()
	settle(t, src)
	require.Equal(t, DisabledInterval, src.dueIn())
	src.Volunteer()
	assert.Never(t, func() bool { return f.calls.Load() > 1 }, 30*time.Millisecond, time.Millisecond)

	src.Invalidate()
	f.results <- fetchResult{t: Tickets{Volunteer: []string{vol}, Lifetime: 15 * time.Minute}}
	src.Volunteer()
	settle(t, src)
	assert.Equal(t, int32(2), f.calls.Load())
	assert.Equal(t, []string{vol}, src.AnsweredVolunteer())
}

// lantern-cloud's 429 or 503 asked this device to back off; a pairing change
// does not override that, so Invalidate leaves the backoff, in flight or
// settled, as it is.
func TestSourceInvalidateKeepsABusyBackoff(t *testing.T) {
	busy := fetchResult{err: fmt.Errorf("ticket request: status 503: %w", ErrUnavailable)}
	f := &fakeFetch{results: make(chan fetchResult)}
	src, _ := newTestSource(f)
	src.Volunteer()
	require.Eventually(t, func() bool { return f.calls.Load() == 1 }, time.Second, time.Millisecond)
	src.Invalidate()
	f.results <- busy
	settle(t, src)
	assert.Equal(t, 2*time.Minute, src.dueIn(), "an invalidation during a busy fetch keeps its backoff")

	src.Invalidate()
	assert.Equal(t, 2*time.Minute, src.dueIn(), "and one after it")
	src.Volunteer()
	assert.Never(t, func() bool { return f.calls.Load() > 1 }, 30*time.Millisecond, time.Millisecond)
}

// A ticket fetch redirected off /helper/ must not be traced either, since the
// redirect carries the device ID header.
func TestFetcherRedirectIsNotTraced(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(mem))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/helper/") {
			http.Redirect(w, r, "/v1/elsewhere", http.StatusTemporaryRedirect)
			return
		}
		_, _ = w.Write([]byte(`{"tickets":[],"lifetime_seconds":600}`))
	}))
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: traces.NewRoundTripper(traces.NewHeaderAnnotatingRoundTripper(http.DefaultTransport))}

	_, err := NewFetcher(client, srv.URL+"/v1").Fetch(context.Background())
	require.NoError(t, err)
	assert.Empty(t, mem.GetSpans())
}

const (
	pairingA = "6f1c2b0e-8a7d-4c1e-9f00-0123456789aa"
	pairingB = "6f1c2b0e-8a7d-4c1e-9f00-0123456789bb"
	tagA     = "helper-aaaaaaaaaaaa"
	tagB     = "helper-bbbbbbbbbbbb"
)

// pairingTicket returns a ticket for pairing in role.
func pairingTicket(t *testing.T, pairing string, role helperticket.Role) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	tk, err := helperticket.Sign(priv, helperticket.Ticket{PairingID: pairing, Role: role, Expires: time.Now().Add(15 * time.Minute)})
	require.NoError(t, err)
	return tk
}

func TestFetcherMapsInviterTagsToPairings(t *testing.T) {
	invA := pairingTicket(t, pairingA, helperticket.RoleInviter)
	invB := pairingTicket(t, pairingB, helperticket.RoleInviter)
	vol := pairingTicket(t, pairingB, helperticket.RoleVolunteer)
	for _, tc := range []struct {
		name string
		tags []string
		want map[string]string
	}{
		{"aligned", []string{tagA, "", tagB}, map[string]string{tagA: pairingA, tagB: pairingB}},
		{"length mismatch is ignored", []string{tagA, ""}, nil},
		{"absent", nil, nil},
		{"a tag on a volunteer ticket is ignored", []string{tagA, tagB, ""}, map[string]string{tagA: pairingA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := map[string]any{"tickets": []string{invA, vol, invB}}
				if tc.tags != nil {
					body["inviter_tags"] = tc.tags
				}
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer srv.Close()
			got, err := NewFetcher(srv.Client(), srv.URL+"/v1").Fetch(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.InviterPairings)
			assert.ElementsMatch(t, []string{invA, invB}, got.Inviter)
		})
	}
}

func TestSourceInviterFor(t *testing.T) {
	invA := pairingTicket(t, pairingA, helperticket.RoleInviter)
	invB := pairingTicket(t, pairingB, helperticket.RoleInviter)
	f := &fakeFetch{results: make(chan fetchResult, 1)}
	src, _ := newTestSource(f)
	changes := make(chan struct{}, 4)
	src.SetOnInviterChange(func() { changes <- struct{}{} })
	count := func() int { return len(changes) }

	tickets, answered := src.InviterFor(tagA)
	assert.Empty(t, tickets)
	assert.False(t, answered, "nothing is known before the first answer")

	f.results <- fetchResult{t: Tickets{Inviter: []string{invA, invB}, InviterPairings: map[string]string{tagA: pairingA, tagB: pairingB}, Lifetime: 15 * time.Minute}}
	settle(t, src)
	tickets, answered = src.InviterFor(tagA)
	assert.Equal(t, []string{invA}, tickets, "only the pairing's tickets")
	assert.True(t, answered)
	tickets, _ = src.InviterFor("helper-cccccccccccc")
	assert.Empty(t, tickets)
	assert.ElementsMatch(t, []string{tagA, tagB}, src.InviterTags())
	awaitChanges(t, count, 1, "the first answer is a change")

	// The same pairings again are no change; losing one is.
	src.Invalidate()
	src.Inviter()
	f.results <- fetchResult{t: Tickets{Inviter: []string{invA, invB}, InviterPairings: map[string]string{tagA: pairingA, tagB: pairingB}, Lifetime: 15 * time.Minute}}
	settle(t, src)
	assertNoChange(t, count, 1)
	src.Invalidate()
	src.Inviter()
	f.results <- fetchResult{t: Tickets{Inviter: []string{invB}, InviterPairings: map[string]string{tagB: pairingB}, Lifetime: 15 * time.Minute}}
	settle(t, src)
	awaitChanges(t, count, 2)
	tickets, _ = src.InviterFor(tagA)
	assert.Empty(t, tickets)
	assert.Equal(t, []string{tagB}, src.InviterTags())

	// helper invites turned off clears them.
	src.Invalidate()
	src.Inviter()
	f.results <- fetchResult{err: ErrDisabled}
	settle(t, src)
	awaitChanges(t, count, 3)
	tickets, answered = src.InviterFor(tagB)
	assert.Empty(t, tickets)
	assert.True(t, answered)
}

// InviterFor must read the tickets and the pairings they came with together:
// a fetch landing between separate reads pairs the tickets from before it
// with the answer it brings, which looks like a pairing with no ticket.
func TestSourceInviterForReadsOneSnapshot(t *testing.T) {
	inv := pairingTicket(t, pairingA, helperticket.RoleInviter)
	release := make(chan struct{})
	src := NewSource(context.Background(), func(context.Context) (Tickets, error) {
		<-release
		return Tickets{Inviter: []string{inv}, InviterPairings: map[string]string{tagA: pairingA}, Lifetime: 15 * time.Minute}, nil
	})
	src.Inviter()
	src.afterRead = func() {
		// Fires only if InviterFor reads through read: the fetch in flight
		// then lands between its reads.
		src.afterRead = nil
		close(release)
		settle(t, src)
	}
	tickets, answered := src.InviterFor(tagA)
	assert.False(t, answered && len(tickets) == 0, "answered, with the pairing known, but no ticket")
	if src.afterRead != nil {
		close(release)
	}
	settle(t, src)
}

// InviterTags is how a status poll learns of rooms-only friends, so it must
// start a fetch even before any pairing is known.
func TestSourceInviterTagsFetches(t *testing.T) {
	inv := pairingTicket(t, pairingA, helperticket.RoleInviter)
	f := &fakeFetch{results: make(chan fetchResult, 1)}
	src, _ := newTestSource(f)
	f.results <- fetchResult{t: Tickets{Inviter: []string{inv}, InviterPairings: map[string]string{tagA: pairingA}, Lifetime: 15 * time.Minute}}
	assert.Empty(t, src.InviterTags())
	require.Eventually(t, func() bool { return len(src.InviterTags()) == 1 }, time.Second, time.Millisecond)
	assert.Equal(t, int32(1), f.calls.Load())
}

// A pairing whose tickets expired and are then renewed changes no pairing,
// but it becomes usable again, which a holder of InviterFor must hear about;
// a renewal of tickets that were still usable must not fire.
func TestSourceOnInviterChangeFiresWhenTicketsBecomeUsable(t *testing.T) {
	inv := pairingTicket(t, pairingA, helperticket.RoleInviter)
	answer := Tickets{Inviter: []string{inv}, InviterPairings: map[string]string{tagA: pairingA}, Lifetime: time.Minute}
	f := &fakeFetch{results: make(chan fetchResult, 1)}
	src, clock := newTestSource(f)
	var changes atomic.Int32
	src.SetOnInviterChange(func() { changes.Add(1) })
	count := func() int { return int(changes.Load()) }
	fetch := func() {
		src.Invalidate()
		f.results <- fetchResult{t: answer}
		src.Inviter()
		settle(t, src)
	}
	fetch()
	awaitChanges(t, count, 1, "the first answer")

	fetch()
	assertNoChange(t, count, 1, "a renewal of usable tickets")

	clock.add(2 * time.Minute)
	f.results <- fetchResult{t: answer}
	tickets, _ := src.InviterFor(tagA)
	require.Empty(t, tickets, "expired, and due for renewal")
	settle(t, src)
	tickets, _ = src.InviterFor(tagA)
	require.NotEmpty(t, tickets, "renewed")
	awaitChanges(t, count, 2, "expired tickets renewed")
}

func TestFetcherReportsPairedBytesUntilDelivered(t *testing.T) {
	var fail atomic.Bool
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		if fail.Load() {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"tickets":[]}`))
	}))
	defer srv.Close()
	u := &Usage{}
	f := NewFetcher(srv.Client(), srv.URL+"/v1").WithUsage(u)
	u.Add(usagePairingB, 30)
	u.Add(usagePairingA, 70)

	fail.Store(true)
	_, err := f.Fetch(context.Background())
	require.ErrorIs(t, err, ErrUnavailable)
	fail.Store(false)
	_, err = f.Fetch(context.Background())
	require.NoError(t, err)
	_, err = f.Fetch(context.Background())
	require.NoError(t, err)

	want := `{"paired_bytes":[{"pairing_id":"` + usagePairingA + `","bytes":70},{"pairing_id":"` + usagePairingB + `","bytes":30}]}`
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, bodies, 3)
	assert.JSONEq(t, want, bodies[0])
	assert.JSONEq(t, want, bodies[1], "a refused report is sent again")
	assert.JSONEq(t, `{}`, bodies[2], "a delivered report is not, and no zero entry goes out")
}

func TestFetcherWithoutUsageSendsAnEmptyObject(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		_, _ = w.Write([]byte(`{"tickets":[]}`))
	}))
	defer srv.Close()
	_, err := NewFetcher(srv.Client(), srv.URL+"/v1").Fetch(context.Background())
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, body)
}

func TestFetcherDropsUsageTheServerRejects(t *testing.T) {
	_, vol := testTickets(t)
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		if strings.Contains(string(b), "paired_bytes") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"tickets":["` + vol + `"]}`))
	}))
	defer srv.Close()
	u := &Usage{}
	f := NewFetcher(srv.Client(), srv.URL+"/v1").WithUsage(u)
	u.Add(usagePairingA, 70)

	got, err := f.Fetch(context.Background())
	require.NoError(t, err, "the fetch goes through without the usage")
	assert.Len(t, got.Volunteer, 1)
	u.Add(usagePairingA, 5)
	_, err = f.Fetch(context.Background())
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, bodies, 4)
	assert.JSONEq(t, `{"paired_bytes":[{"pairing_id":"`+usagePairingA+`","bytes":70}]}`, bodies[0])
	assert.JSONEq(t, `{}`, bodies[1], "resent once without the usage")
	assert.JSONEq(t, `{"paired_bytes":[{"pairing_id":"`+usagePairingA+`","bytes":5}]}`, bodies[2],
		"rejected usage is dropped, not sent again")
	assert.JSONEq(t, `{}`, bodies[3])
}

func TestFetcherWithoutUsageIsNotResentOn400(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	_, err := NewFetcher(srv.Client(), srv.URL+"/v1").WithUsage(&Usage{}).Fetch(context.Background())
	require.Error(t, err)
	assert.Equal(t, int32(1), calls.Load())
}

func TestFetcherKeepsUsageOnServerError(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusServiceUnavailable} {
		var fail atomic.Bool
		var mu sync.Mutex
		var bodies []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			bodies = append(bodies, string(b))
			mu.Unlock()
			if fail.Load() {
				w.WriteHeader(status)
				return
			}
			_, _ = w.Write([]byte(`{"tickets":[]}`))
		}))
		u := &Usage{}
		f := NewFetcher(srv.Client(), srv.URL+"/v1").WithUsage(u)
		u.Add(usagePairingA, 70)

		fail.Store(true)
		_, err := f.Fetch(context.Background())
		require.Error(t, err, "status %d", status)
		fail.Store(false)
		_, err = f.Fetch(context.Background())
		require.NoError(t, err)
		srv.Close()

		want := `{"paired_bytes":[{"pairing_id":"` + usagePairingA + `","bytes":70}]}`
		mu.Lock()
		require.Len(t, bodies, 2, "status %d is not resent", status)
		assert.JSONEq(t, want, bodies[1], "status %d keeps the usage for the next fetch", status)
		mu.Unlock()
	}
}

// A ticket request carries pairing IDs, so a redirect to another origin must
// not replay it there.
func TestFetcherRefusesCrossOriginRedirects(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var other atomic.Int32
			elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				other.Add(1)
				_, _ = w.Write([]byte(`{"tickets":[]}`))
			}))
			defer elsewhere.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, elsewhere.URL+r.URL.Path, code)
			}))
			defer srv.Close()
			u := &Usage{}
			u.Add(usagePairingA, 70)

			_, err := NewFetcher(srv.Client(), srv.URL+"/v1").WithUsage(u).Fetch(context.Background())
			require.Error(t, err)
			assert.Zero(t, other.Load(), "the other origin never receives the request")
			assert.Equal(t, []PairedBytes{{PairingID: usagePairingA, Bytes: 70}}, u.Take(), "the usage is kept for the next fetch")
		})
	}
}

func TestFetcherFollowsSameOriginRedirects(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/helper/tickets" {
			http.Redirect(w, r, "/v2/helper/tickets", http.StatusPermanentRedirect)
			return
		}
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		_, _ = w.Write([]byte(`{"tickets":[]}`))
	}))
	defer srv.Close()
	u := &Usage{}
	u.Add(usagePairingA, 70)

	_, err := NewFetcher(srv.Client(), srv.URL+"/v1").WithUsage(u).Fetch(context.Background())
	require.NoError(t, err)
	assert.JSONEq(t, `{"paired_bytes":[{"pairing_id":"`+usagePairingA+`","bytes":70}]}`, body)
	assert.Empty(t, u.Take())
}

// WaitFetched starts the first fetch and waits for it to finish, whatever its
// outcome, and a later call returns at once.
func TestSourceWaitFetched(t *testing.T) {
	f := &fakeFetch{results: make(chan fetchResult)}
	src := NewSource(context.Background(), f.fetch)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	assert.False(t, src.WaitFetched(ctx), "no fetch has finished yet")
	require.Eventually(t, func() bool { return f.calls.Load() == 1 }, time.Second, time.Millisecond)

	done := make(chan bool)
	go func() { done <- src.WaitFetched(context.Background()) }()
	f.results <- fetchResult{err: errors.New("unreachable")}
	select {
	case ok := <-done:
		assert.True(t, ok, "a failed fetch has still finished")
	case <-time.After(time.Second):
		t.Fatal("WaitFetched did not return after the fetch finished")
	}
	assert.True(t, src.WaitFetched(context.Background()))
	assert.Equal(t, int32(1), f.calls.Load(), "waiting again does not fetch again before the retry is due")
}
