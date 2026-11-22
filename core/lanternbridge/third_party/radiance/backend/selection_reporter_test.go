package backend

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	lbA "github.com/getlantern/lantern-box/adapter"

	"github.com/getlantern/radiance/servers"
)

// testReporter builds a reporter whose clock is driven by the returned pointer,
// so a test can advance time deterministically between report calls.
func testReporter(t *testing.T, url string) (*selectionReporter, *time.Time) {
	t.Helper()
	clock := time.Unix(0, 0).UTC()
	sr := &selectionReporter{
		httpClient:   http.DefaultClient,
		reportURL:    url,
		now:          func() time.Time { return clock },
		baseline:     clock,
		lastReported: make(map[string]time.Time),
	}
	return sr, &clock
}

func testReporterWithServer(t *testing.T, handler http.HandlerFunc) (*selectionReporter, *time.Time, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(handler)
	sr, clock := testReporter(t, srv.URL)
	sr.httpClient = srv.Client()
	return sr, clock, srv
}

func history(failures ...lbA.UserFailure) servers.SelectionHistory {
	return servers.SelectionHistory{UserFailures: failures}
}

func reportAt(
	t *testing.T,
	sr *selectionReporter,
	clock *time.Time,
	at int,
	snapshot map[string]servers.SelectionHistory,
	tokens map[string]string,
) error {
	t.Helper()

	*clock = time.Unix(int64(at), 0).UTC()
	return sr.report(t.Context(), snapshot, tokens)
}

func decodeReportRequest(t *testing.T, body []byte) selectionReportRequest {
	t.Helper()

	var got selectionReportRequest
	require.NoError(t, json.Unmarshal(body, &got))
	return got
}

func TestSelectionReporter_Report_PostsTokenedEntries(t *testing.T) {
	var gotBody []byte
	sr, clock, srv := testReporterWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	want := []selectionReportEntry{
		{
			ReportToken:   "tok-1",
			WindowSeconds: 300,
			Failures: []lbA.UserFailure{
				{At: time.Unix(1, 0).UTC(), Kind: lbA.UserFailureDial},
				{At: time.Unix(2, 0).UTC(), Kind: lbA.UserFailureReset},
			},
		},
	}
	snapshot := map[string]servers.SelectionHistory{
		"srv-1": {
			UserFailures: want[0].Failures,
		},
	}
	tokens := map[string]string{"srv-1": want[0].ReportToken}
	require.NoError(t, reportAt(t, sr, clock, want[0].WindowSeconds, snapshot, tokens))

	got := decodeReportRequest(t, gotBody)
	assert.Equal(t, want, got.Reports, "the report request must contain the tokened failures and window")
}

func TestSelectionReporter_Report_SkipsTagsWithoutTokenOrFailures(t *testing.T) {
	var gotBody []byte
	sr, clock, srv := testReporterWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	snapshot := map[string]servers.SelectionHistory{
		"has-token":    {UserFailures: []lbA.UserFailure{{At: time.Unix(1, 0).UTC(), Kind: lbA.UserFailureStall}}},
		"no-token":     {UserFailures: []lbA.UserFailure{{At: time.Unix(1, 0).UTC(), Kind: lbA.UserFailureStall}}},
		"no-failures":  {},
		"token-nofail": {},
	}
	tokens := map[string]string{"has-token": "tok", "no-failures": "tok2", "token-nofail": "tok3"}
	require.NoError(t, reportAt(t, sr, clock, 300, snapshot, tokens))

	got := decodeReportRequest(t, gotBody)
	require.Len(t, got.Reports, 1, "only the tag with both a token and failures is reported")
	assert.Equal(t, "tok", got.Reports[0].ReportToken)
}

func TestSelectionReporter_Report_NoopWhenNothingReportable(t *testing.T) {
	sr, clock, srv := testReporterWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Fail(t, "report should not POST when there are no tokened entries")
	})
	defer srv.Close()

	snapshot := map[string]servers.SelectionHistory{
		"a": {UserFailures: []lbA.UserFailure{{At: time.Unix(1, 0).UTC(), Kind: lbA.UserFailureStall}}},
	}
	// No token for "a" → nothing attributable → no request.
	require.NoError(t, reportAt(t, sr, clock, 300, snapshot, map[string]string{}))
}

func TestSelectionReporter_Report_ErrorOnNon2xx(t *testing.T) {
	sr, clock, srv := testReporterWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	snapshot := map[string]servers.SelectionHistory{
		"a": {UserFailures: []lbA.UserFailure{{At: time.Unix(1, 0).UTC(), Kind: lbA.UserFailureStall}}},
	}
	assert.Error(t, reportAt(t, sr, clock, 300, snapshot, map[string]string{"a": "tok"}))
	assert.True(t, sr.lastReported["a"].IsZero(), "lastReported should not change when the POST fails")
}

func TestSelectionReporter_Report_DrainsAndWidensWindow(t *testing.T) {
	var bodies [][]byte
	sr, clock, srv := testReporterWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, body)
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	tokens := map[string]string{"a": "tok"}

	require.NoError(t, reportAt(t, sr, clock, 100, map[string]servers.SelectionHistory{
		"a": history(lbA.UserFailure{At: time.Unix(10, 0).UTC(), Kind: lbA.UserFailureDial}),
	}, tokens))

	// The already-reported failure is still in the sliding window, plus a new one.
	require.NoError(t, reportAt(t, sr, clock, 200, map[string]servers.SelectionHistory{
		"a": history(
			lbA.UserFailure{At: time.Unix(10, 0).UTC(), Kind: lbA.UserFailureDial},
			lbA.UserFailure{At: time.Unix(150, 0).UTC(), Kind: lbA.UserFailureStall},
		),
	}, tokens))

	require.Len(t, bodies, 2, "both reports carry a fresh failure and POST")

	r1 := decodeReportRequest(t, bodies[0])
	r2 := decodeReportRequest(t, bodies[1])

	require.Len(t, r1.Reports[0].Failures, 1)
	assert.Equal(t, time.Unix(10, 0).UTC(), r1.Reports[0].Failures[0].At.UTC())
	assert.Equal(t, 100, r1.Reports[0].WindowSeconds, "first window is now - baseline")

	require.Len(t, r2.Reports[0].Failures, 1, "the already-reported failure is drained")
	assert.Equal(t, time.Unix(150, 0).UTC(), r2.Reports[0].Failures[0].At.UTC())
	assert.Equal(t, 100, r2.Reports[0].WindowSeconds, "second window is now - first report instant")
}

// A failed POST must not drop the failures it tried to send: the next report
// re-sends them over a widened window rather than losing them.
func TestSelectionReporter_Report_RetainsFailuresAfterFailedPost(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	var lastBody []byte
	sr, clock, srv := testReporterWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		lastBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	tokens := map[string]string{"a": "tok"}
	snapshot := map[string]servers.SelectionHistory{
		"a": {UserFailures: []lbA.UserFailure{{At: time.Unix(10, 0).UTC(), Kind: lbA.UserFailureReset}}},
	}

	require.Error(t, reportAt(t, sr, clock, 100, snapshot, tokens))

	fail.Store(false)
	require.NoError(t, reportAt(t, sr, clock, 200, snapshot, tokens))

	got := decodeReportRequest(t, lastBody)
	require.Len(t, got.Reports, 1)
	require.Len(t, got.Reports[0].Failures, 1, "the failure survived the failed POST and is re-sent")
	assert.Equal(t, time.Unix(10, 0).UTC(), got.Reports[0].Failures[0].At.UTC())
	assert.Equal(t, 200, got.Reports[0].WindowSeconds, "window widens to now - baseline after the retry")
}

func TestSelectionReporter_Reset_ReanchorsWindow(t *testing.T) {
	var body []byte
	sr, clock, srv := testReporterWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	tokens := map[string]string{"a": "tok"}

	require.NoError(t, reportAt(t, sr, clock, 100, map[string]servers.SelectionHistory{
		"a": history(lbA.UserFailure{At: time.Unix(10, 0).UTC(), Kind: lbA.UserFailureDial}),
	}, tokens))

	*clock = time.Unix(500, 0).UTC()
	sr.reset()

	require.NoError(t, reportAt(t, sr, clock, 560, map[string]servers.SelectionHistory{
		"a": history(lbA.UserFailure{At: time.Unix(520, 0).UTC(), Kind: lbA.UserFailureStall}),
	}, tokens))

	got := decodeReportRequest(t, body)
	require.Len(t, got.Reports, 1)
	assert.Equal(t, 60, got.Reports[0].WindowSeconds, "window is measured from the reset baseline")
}

// A report whose POST straddles a reset (a reconnect) must not write its
// watermark into the new connection's state, or that tag's first post-reconnect
// report would measure its window from the stale instant.
func TestSelectionReporter_Report_ResetDuringPostDropsStaleWatermark(t *testing.T) {
	sr, clock := testReporter(t, "")
	reset := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reset lands while the POST is in flight, mimicking a reconnect.
		sr.reset()
		close(reset)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	sr.httpClient = srv.Client()
	sr.reportURL = srv.URL

	require.NoError(t, reportAt(t, sr, clock, 100, map[string]servers.SelectionHistory{
		"a": history(lbA.UserFailure{At: time.Unix(10, 0).UTC(), Kind: lbA.UserFailureDial}),
	}, map[string]string{"a": "tok"}))
	<-reset

	assert.True(t, sr.lastReported["a"].IsZero(), "a watermark from a report that straddled reset must be dropped")
}

func TestRunReportLoop_StopsWhenIntervalDropsToZero(t *testing.T) {
	intervals := []time.Duration{time.Millisecond, time.Millisecond, 0}
	i := 0
	interval := func() time.Duration {
		if i >= len(intervals) {
			return 0
		}
		d := intervals[i]
		i++
		return d
	}
	var reports int
	runReportLoop(t.Context(), interval, func() { reports++ })
	assert.Equal(t, 2, reports, "one report per positive interval before the disabling zero")
}

func TestRunReportLoop_NeverStartsWhenDisabled(t *testing.T) {
	var reports int
	runReportLoop(t.Context(), func() time.Duration { return 0 }, func() { reports++ })
	assert.Zero(t, reports, "a disabled interval reports nothing")
}

func TestRunReportLoop_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		runReportLoop(ctx, func() time.Duration { return time.Hour }, func() {})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		assert.Fail(t, "runReportLoop did not stop after context cancel")
	}
}
