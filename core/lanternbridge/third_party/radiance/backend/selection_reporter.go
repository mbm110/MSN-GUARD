package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/getlantern/kindling"
	"github.com/getlantern/lantern-box/adapter"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/servers"
)

const (
	// banditReportPath is joined onto the config API base URL.
	banditReportPath = "/bandit/report"

	selectionReportTimeout = 30 * time.Second
)

// selectionReportEntry is one route's reported failure window.
type selectionReportEntry struct {
	// ReportToken is the server-issued opaque HMAC token for the route.
	ReportToken string `json:"report_token"`
	// Failures is the list of failures since the last confirmed report.
	Failures []adapter.UserFailure `json:"failures"`
	// WindowSeconds is the elapsed accumulation period for the failures, measured
	// from the last confirmed report.
	WindowSeconds int `json:"window_seconds"`
}

type selectionReportRequest struct {
	Reports []selectionReportEntry `json:"entries"`
}

// selectionReporter sends route-selection failure history to the server.
//
// Reporting is watermark-based:
//   - each successful report advances the tag's watermark to the report time
//   - later reports include only failures newer than that watermark
//   - failed reports do not advance the watermark, so data is retried
//
// reset() starts a new reporting epoch for a new connection session.
type selectionReporter struct {
	httpClient *http.Client
	reportURL  string
	now        func() time.Time

	mu sync.Mutex
	// epoch is bumped by reset and guards a lagging report from writing into a newer connection's state.
	epoch uint64
	// baseline is the anchor for a tag's first report, set per connection by reset.
	baseline time.Time
	// lastReported maps each tag to its last confirmed report timestamp.
	lastReported map[string]time.Time
}

// reporterState is an immutable snapshot of reporter state used to build a
// report outside the mutex.
type reporterState struct {
	epoch        uint64
	baseline     time.Time
	lastReported map[string]time.Time
}

// selectionReportPayload contains the payload and metadata needed to update
// lastReported after a successful POST.
type selectionReportPayload struct {
	epoch          uint64
	entries        []selectionReportEntry
	reportedTags   []string
	skippedNoToken int
}

func newSelectionReporter(httpClient *http.Client) *selectionReporter {
	return &selectionReporter{
		httpClient:   httpClient,
		reportURL:    common.GetBaseURL() + banditReportPath,
		now:          time.Now,
		lastReported: make(map[string]time.Time),
	}
}

// reset clears every tag's lastReported timestamp and re-anchors the first
// report window to the current time. It should be called when a new VPN
// connection session starts.
func (sr *selectionReporter) reset() {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	sr.epoch++
	sr.baseline = sr.now()
	sr.lastReported = make(map[string]time.Time)
}

// report posts reportable failures for all tokened tags in snapshot.
// If nothing is reportable, it returns nil without sending a request.
func (sr *selectionReporter) report(
	ctx context.Context,
	snapshot map[string]servers.SelectionHistory,
	tokens map[string]string,
) error {
	span := trace.SpanFromContext(ctx)
	now := sr.now()
	prepared := sr.prepareReport(now, snapshot, tokens)
	if len(prepared.entries) == 0 {
		if prepared.skippedNoToken > 0 {
			slog.Debug(
				"Selection report skipped: no reportable entries",
				"skippedNoToken", prepared.skippedNoToken,
			)
		}
		return nil
	}

	span.AddEvent("selection_report", trace.WithAttributes(
		attribute.Int("entries", len(prepared.entries)),
		attribute.Int("skippedNoToken", prepared.skippedNoToken),
	))
	if err := sr.post(ctx, prepared.entries); err != nil {
		return err
	}

	sr.markReported(prepared.epoch, now, prepared.reportedTags)
	slog.Debug(
		"Reported selection history",
		"entries", len(prepared.entries),
		"skippedNoToken", prepared.skippedNoToken,
	)
	return nil
}

// prepareReport converts a snapshot into a POST payload using a point-in-time
// copy of reporter state.
func (sr *selectionReporter) prepareReport(
	now time.Time,
	snapshot map[string]servers.SelectionHistory,
	tokens map[string]string,
) selectionReportPayload {
	state := sr.snapshotState()
	result := selectionReportPayload{epoch: state.epoch}

	for _, tag := range sortedSnapshotTags(snapshot) {
		token := tokens[tag]
		if token == "" {
			result.skippedNoToken++
			continue
		}

		lastReported := state.lastReported[tag]
		if lastReported.IsZero() {
			lastReported = state.baseline
		}

		failures := failuresSince(snapshot[tag].UserFailures, lastReported)
		if len(failures) == 0 {
			continue
		}

		result.entries = append(result.entries, selectionReportEntry{
			ReportToken:   token,
			Failures:      failures,
			WindowSeconds: reportWindowSeconds(now, lastReported),
		})
		result.reportedTags = append(result.reportedTags, tag)
	}

	return result
}

// snapshotState copies the mutable reporter state so report preparation can run
// without holding the mutex.
func (sr *selectionReporter) snapshotState() reporterState {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	lastReported := make(map[string]time.Time, len(sr.lastReported))
	for tag, ts := range sr.lastReported {
		lastReported[tag] = ts
	}

	return reporterState{
		epoch:        sr.epoch,
		baseline:     sr.baseline,
		lastReported: lastReported,
	}
}

// markReported advances lastReported for the tags that were successfully sent.
// If reset() ran during the POST, the epoch will differ and the stale update is
// discarded.
func (sr *selectionReporter) markReported(epoch uint64, reportedAt time.Time, tags []string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if sr.epoch != epoch {
		return
	}

	for _, tag := range tags {
		sr.lastReported[tag] = reportedAt
	}
}

func (sr *selectionReporter) post(ctx context.Context, entries []selectionReportEntry) error {
	body, err := json.Marshal(selectionReportRequest{Reports: entries})
	if err != nil {
		return fmt.Errorf("marshal selection report: %w", err)
	}
	req, err := common.NewRequestWithHeaders(ctx, http.MethodPost, sr.reportURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build selection report request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The payload is a stateless snapshot, so transport-level retry/failover is safe.
	req.Header.Set(kindling.IdempotentHeader, "1")

	resp, err := sr.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("post selection report: %w", err)
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("selection report rejected: %s", resp.Status)
	}
	return nil
}

// sortedSnapshotTags returns snapshot keys in stable order to keep payload
// generation deterministic.
func sortedSnapshotTags(snapshot map[string]servers.SelectionHistory) []string {
	tags := make([]string, 0, len(snapshot))
	for tag := range snapshot {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

// failuresSince returns only failures strictly newer than since.
func failuresSince(failures []adapter.UserFailure, since time.Time) []adapter.UserFailure {
	filtered := make([]adapter.UserFailure, 0, len(failures))
	for _, failure := range failures {
		if failure.At.After(since) {
			filtered = append(filtered, failure)
		}
	}
	return filtered
}

// reportWindowSeconds converts a report window to whole seconds and clamps it
// to a minimum of 1.
func reportWindowSeconds(now, since time.Time) int {
	seconds := int(now.Sub(since).Seconds())
	return max(1, seconds)
}
