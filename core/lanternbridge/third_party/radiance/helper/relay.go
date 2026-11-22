package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/sameorigin"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/traces"
)

// relayPaths are the HelperService operations the app may relay, by the name
// it uses, mapped to their paths under the API base URL. Only these reach
// lantern-cloud: the relay is not a general proxy.
var relayPaths = map[string]string{
	"invites":        "/helper/invites",
	"invites/claim":  "/helper/invites/claim",
	"invites/get":    "/helper/invites/get",
	"invites/decide": "/helper/invites/decide",
	"pairings":       "/helper/pairings",
	"pairings/end":   "/helper/pairings/end",
}

// OpRefreshTickets is a local operation. It runs onChange, so the ticket
// Source fetches at its next read, for a pairing the app has just seen appear.
const OpRefreshTickets = "tickets/refresh"

// invalidatingOps change this device's pairings when they succeed.
var invalidatingOps = map[string]bool{"invites/claim": true, "invites/decide": true, "pairings/end": true}

const (
	relayTimeout   = 30 * time.Second
	maxRelayBody   = 64 << 10
	maxRelayErrLen = 200
)

// ErrUnknownOp is Relay's error for an operation it does not relay.
var ErrUnknownOp = errors.New("helper: unknown relay operation")

// RelayResult is lantern-cloud's answer to a relayed request: its status, its
// JSON body on a 2xx, and its error text otherwise.
type RelayResult struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Relayer sends the app's helper-invite requests to lantern-cloud as this
// device, through the same circumvention-capable client as the rest of the
// API. The app's Go core builds every body. They carry invite hashes,
// public keys and encrypted names, never an invite secret, and nothing here
// logs a body or an answer.
type Relayer struct {
	httpClient *http.Client
	baseURL    string
	onChange   func()
}

// NewRelayer returns a Relayer. baseURL includes the API version segment, as
// common.GetBaseURL() returns it.
// onChange, which may be nil, runs after an operation that changes this
// device's pairings succeeds.
// The Relayer uses a copy of httpClient that follows redirects only within
// the request's origin.
func NewRelayer(httpClient *http.Client, baseURL string, onChange func()) *Relayer {
	return &Relayer{httpClient: sameorigin.Client(httpClient, "helper: relay"), baseURL: baseURL, onChange: onChange}
}

func (r *Relayer) changed() {
	if r.onChange != nil {
		r.onChange()
	}
}

// IsRelayOp reports whether op is a HelperService operation Relay forwards.
func IsRelayOp(op string) bool {
	_, ok := relayPaths[op]
	return ok
}

// Relay sends body to op's HelperService path. A transport failure is an
// error, and any HTTP status is a result. After a claim, decision or ending
// succeeds, onChange runs.
func (r *Relayer) Relay(ctx context.Context, op string, body []byte) (RelayResult, error) {
	if op == OpRefreshTickets {
		r.changed()
		return RelayResult{Status: http.StatusOK, Body: json.RawMessage("{}")}, nil
	}
	path, ok := relayPaths[op]
	if !ok {
		return RelayResult{}, ErrUnknownOp
	}
	if len(body) == 0 {
		body = []byte("{}")
	}
	// Kindling records its attempts as events on the span in the request's
	// context, and a helper call, or a redirect from one, must not show up
	// in any trace.
	ctx = traces.Untraced(ctx)
	ctx, cancel := context.WithTimeout(ctx, relayTimeout)
	defer cancel()
	req, err := common.NewRequestWithHeaders(ctx, http.MethodPost, r.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return RelayResult{}, fmt.Errorf("build helper request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if val := settings.GetString(settings.FeatureOverridesKey); val != "" {
		req.Header.Set("X-Lantern-Feature-Override", val)
	}
	// The transport error is not wrapped: net/http errors quote the URL.
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return RelayResult{}, errors.New("helper request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRelayBody+1))
	if err != nil || len(data) > maxRelayBody {
		return RelayResult{}, errors.New("helper response unreadable")
	}
	out := RelayResult{Status: resp.StatusCode}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// lantern-cloud's JSON bindings answer an Empty with no body unless
		// told otherwise; that is a success with nothing to return.
		if len(bytes.TrimSpace(data)) == 0 {
			data = []byte("{}")
		}
		if !json.Valid(data) {
			return RelayResult{}, errors.New("helper response is not JSON")
		}
		out.Body = data
		if invalidatingOps[op] {
			r.changed()
		}
		return out, nil
	}
	text := strings.TrimSpace(string(data))
	if len(text) > maxRelayErrLen {
		text = text[:maxRelayErrLen]
	}
	// After the cut, so a rune it split is dropped.
	out.Error = strings.ToValidUTF8(text, "")
	return out, nil
}
