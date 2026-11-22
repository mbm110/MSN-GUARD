// Package peer implements the client side of "Share My Connection",
// including the thin HTTP client for the /v1/peer/* endpoints.
package peer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/sameorigin"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/helper"
)

type RegisterRequest struct {
	ExternalIP   string `json:"external_ip"`
	ExternalPort uint16 `json:"external_port"`
	InternalPort uint16 `json:"internal_port"`
	// ServePool is set, to false, only when the route should serve just this
	// device's helper pairings. Absent means the route also serves the
	// general pool, which is what servers that predate the field assume.
	ServePool *bool `json:"serve_pool,omitempty"`
}

type RegisterResponse struct {
	RouteID                  string `json:"route_id"`
	ServerConfig             string `json:"server_config"`
	HeartbeatIntervalSeconds int64  `json:"heartbeat_interval_seconds"`
	// PairingShortIDs are the short IDs, 16 lowercase hex characters each,
	// the inbound must accept for this device's helper pairings, beside the
	// launch config's own. They are only meaningful when
	// PairingShortIDsKnown is true.
	PairingShortIDs []string `json:"pairing_short_ids"`
	// PairingShortIDsKnown says the server vouches for PairingShortIDs as the
	// complete set, so an empty list means no pairings. False, or absent
	// from an older server, means the peer keeps the set it has.
	PairingShortIDsKnown bool `json:"pairing_short_ids_known"`
	// PairingShortIDsRevision is when the server computed PairingShortIDs,
	// in Unix milliseconds, so the peer never replaces a set with an older
	// one. Non-zero exactly when PairingShortIDsKnown is true.
	PairingShortIDsRevision Revision `json:"pairing_short_ids_revision"`
	// PairingShortIDSets is PairingShortIDs grouped by pairing, so the peer
	// can tell which pairing a connection came through. Joined in order, the
	// groups' IDs are PairingShortIDs. Covered by the same Known and
	// Revision. Absent from servers that predate it.
	PairingShortIDSets []PairingShortIDSet `json:"pairing_short_id_sets"`
}

// PairingShortIDSet is one pairing's short IDs. PairingID identifies a
// friend relationship and must never be logged or persisted.
type PairingShortIDSet struct {
	PairingID string   `json:"pairing_id"`
	ShortIDs  []string `json:"short_ids"`
}

// Revision is an int64 that decodes from a JSON number or, as lantern-cloud's
// protojson encoding sends int64s, a JSON string.
type Revision int64

func (r *Revision) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		b = []byte(s)
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("revision: %w", err)
	}
	*r = Revision(n)
	return nil
}

// HeartbeatResponse carries the current pairing short IDs, which rotate with
// the server's 24-hour epoch. When PairingShortIDsKnown is true the peer
// replaces its pairing set with PairingShortIDs, so an ended pairing drops
// out here; otherwise it keeps the set it has.
type HeartbeatResponse struct {
	PairingShortIDs         []string `json:"pairing_short_ids"`
	PairingShortIDsKnown    bool     `json:"pairing_short_ids_known"`
	PairingShortIDsRevision Revision `json:"pairing_short_ids_revision"`
	// PairingShortIDSets is as for RegisterResponse.
	PairingShortIDSets []PairingShortIDSet `json:"pairing_short_id_sets"`
}

type LifecycleRequest struct {
	RouteID string `json:"route_id"`
}

// HeartbeatRequest is LifecycleRequest plus the peer's current load. Separate
// from LifecycleRequest so verify and deregister, which have no load to
// report, don't carry a field that would read as "zero clients".
type HeartbeatRequest struct {
	RouteID string `json:"route_id"`
	// ActiveClients counts distinct remote IPs with at least one open
	// connection, not connections: samizdat multiplexes many H2 streams over
	// one TCP conn, and a client may hold several, so a connection count would
	// overstate how many people are actually being helped.
	ActiveClients int `json:"active_clients"`
	// RelayedBytes is the bytes relayed since the last heartbeat that
	// succeeded; omitted when zero.
	RelayedBytes uint64 `json:"relayed_bytes,omitempty"`
	// PairedBytes omits traffic that came through no pairing, so its sum can
	// be less than RelayedBytes.
	PairedBytes []helper.PairedBytes `json:"paired_bytes,omitempty"`
}

// decodeError is a 2xx response whose body did not decode, so callers can
// tell it from a request the server never accepted.
type decodeError struct{ err error }

func (e *decodeError) Error() string { return "decode response: " + e.err.Error() }
func (e *decodeError) Unwrap() error { return e.err }

// APIError carries the server's HTTP status and body.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("peer api: status=%d body=%s", e.Status, e.Body)
}

type API struct {
	httpClient *http.Client
	baseURL    string
	deviceID   string
}

// NewAPI constructs the client. baseURL must already include the API
// version path segment — common.GetBaseURL() returns an env-specific URL
// suffixed with either ".../v1" or ".../api/v1". Per-endpoint paths are
// appended to baseURL without re-adding any version segment, matching
// how every other radiance caller of common.GetBaseURL composes URLs.
// The API uses a copy of httpClient that follows redirects only within the
// request's origin, since a heartbeat body can carry pairing IDs.
func NewAPI(httpClient *http.Client, baseURL, deviceID string) *API {
	return &API{httpClient: sameorigin.Client(httpClient, "peer api"), baseURL: baseURL, deviceID: deviceID}
}

func (a *API) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	var resp RegisterResponse
	if err := a.do(ctx, http.MethodPost, "/peer/register", req, &resp); err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	return &resp, nil
}

// Verify asks lantern-cloud to dial the peer's external endpoint through a
// freshly-built samizdat client. Called after Start has finished bringing
// up sing-box locally so the server's verifier hits a live listener with
// the matching creds. Server-side failure deprecates the row + returns
// 422.
func (a *API) Verify(ctx context.Context, routeID string) error {
	if err := a.do(ctx, http.MethodPost, "/peer/verify", LifecycleRequest{RouteID: routeID}, nil); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return nil
}

// Heartbeat extends the peer route's TTL and reports how many distinct client
// devices are currently connected. The server owner-gates via
// X-Lantern-Device-Id, so a leaked route_id can't be used by another device
// to keep the registration alive.
//
// activeClients lets the server stop handing this peer to new clients once it
// is carrying its share. It is reported rather than inferred because the
// server has no other view of it: assignment records only exist for WireGuard
// variants, and a peer serves samizdat. Reporting also self-corrects — a count
// measured now cannot go stale the way an assignment log does when clients
// simply disappear.
//
// It returns the pairing short IDs the inbound must accept. A 2xx means the
// server has recorded the heartbeat, so a body that doesn't decode, including
// the empty body of a server that predates the IDs, never fails it: the
// response comes back as not known and the peer keeps the set it has.
//
// A non-2xx response means the heartbeat, and the usage it carries, was not
// recorded; a transport error or timeout leaves that unknown.
func (a *API) Heartbeat(ctx context.Context, routeID string, activeClients int, usage RelayUsage) (*HeartbeatResponse, error) {
	req := HeartbeatRequest{RouteID: routeID, ActiveClients: activeClients,
		RelayedBytes: usage.RelayedBytes, PairedBytes: usage.PairedBytes}
	var resp HeartbeatResponse
	err := a.do(ctx, http.MethodPost, "/peer/heartbeat", req, &resp)
	var de *decodeError
	if errors.As(err, &de) {
		if !errors.Is(de.err, io.EOF) {
			slog.Debug("peer heartbeat response unreadable; pairing short IDs not known")
		}
		return &HeartbeatResponse{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("heartbeat: %w", err)
	}
	return &resp, nil
}

func (a *API) Deregister(ctx context.Context, routeID string) error {
	if err := a.do(ctx, http.MethodPost, "/peer/deregister", LifecycleRequest{RouteID: routeID}, nil); err != nil {
		return fmt.Errorf("deregister: %w", err)
	}
	return nil
}

func (a *API) do(ctx context.Context, method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}
	// Use common.NewRequestWithHeaders so peer endpoints carry the same
	// header set as /config-new — most importantly X-Lantern-Config-Client-IP,
	// which the server's util.ClientIPWithAddr prefers over X-Forwarded-For
	// and RemoteAddr. Without it, register/verify can resolve a different
	// IP than radiance has detected as the client's public IP, and the
	// server's verifier dials an address the peer's listener isn't bound to.
	r, err := common.NewRequestWithHeaders(ctx, method, a.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	// NewRequestWithHeaders sets DeviceIDHeader from settings; override with
	// the API's bound deviceID for parity with the prior behavior in case
	// the two ever diverge.
	r.Header.Set(common.DeviceIDHeader, a.deviceID)
	// The server-side gate rejects register/heartbeat/deregister regardless of
	// the local toggle unless this header (fed by RADIANCE_FEATURE_OVERRIDES)
	// is set.
	if val := settings.GetString(settings.FeatureOverridesKey); val != "" {
		r.Header.Set("X-Lantern-Feature-Override", val)
	}

	resp, err := a.httpClient.Do(r)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		const maxBody = 4096
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		return &APIError{Status: resp.StatusCode, Body: string(bytes.TrimSpace(buf))}
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return &decodeError{err: err}
		}
	}
	return nil
}
