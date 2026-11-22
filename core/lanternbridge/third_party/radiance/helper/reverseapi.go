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

const (
	reverseTimeout   = 30 * time.Second
	maxReverseBody   = 1 << 20
	maxReverseErrLen = 200
)

// ErrReverseDisabled means lantern-cloud has reverse routes off for this
// client. It is a server-side flag state, so it is not permanent.
var ErrReverseDisabled = errors.New("helper: reverse routes disabled")

// ReverseBlob is one pairing's sealed reverse route. Blob is opaque to
// lantern-cloud and travels as standard base64.
type ReverseBlob struct {
	PairingID string `json:"pairing_id"`
	Blob      []byte `json:"blob"`
	Version   int    `json:"version"`
}

// ReverseRegisterResponse is lantern-cloud's answer to Register.
type ReverseRegisterResponse struct {
	// ObservedIP is the address lantern-cloud saw the request come from, or
	// "" when it could not tell.
	ObservedIP string `json:"observed_ip"`
	// Tags maps each named pairing this device invited to its helper outbound
	// tag.
	Tags map[string]string `json:"tags"`
}

// ReverseRoutesResponse is lantern-cloud's answer to Routes.
type ReverseRoutesResponse struct {
	Routes []ReverseBlob `json:"routes"`
	// BridgeConfig is sing-box JSON for the helper's bridge, or "" when there
	// is none.
	BridgeConfig string `json:"bridge_config"`
}

// ReverseAPIError is a non-2xx answer other than 404. Body is the start of
// the server's text and may name a pairing, so Error omits it.
type ReverseAPIError struct {
	Status int
	Body   string
}

func (e *ReverseAPIError) Error() string {
	return fmt.Sprintf("reverse api: status %d", e.Status)
}

// ReverseAPI calls lantern-cloud's reverse-route endpoints as one device.
type ReverseAPI struct {
	httpClient *http.Client
	baseURL    string
	deviceID   string
}

// NewReverseAPI returns a ReverseAPI. baseURL includes the API version
// segment, as common.GetBaseURL() returns it. The ReverseAPI uses a copy of
// httpClient that follows redirects only within the request's origin, since
// a request body carries sealed routes.
func NewReverseAPI(httpClient *http.Client, baseURL, deviceID string) *ReverseAPI {
	return &ReverseAPI{
		httpClient: sameorigin.Client(httpClient, "helper: reverse"),
		baseURL:    baseURL,
		deviceID:   deviceID,
	}
}

type reverseRegisterRequest struct {
	Routes []ReverseBlob `json:"routes"`
}

// Register stores the routes of the named pairings this device invited, and
// drops a named pairing's route that lantern-cloud refuses. Routes of pairings
// it does not name are left to expire; only Deregister withdraws them at once.
// An empty routes stores nothing but still reports ObservedIP.
func (a *ReverseAPI) Register(ctx context.Context, routes []ReverseBlob) (*ReverseRegisterResponse, error) {
	if routes == nil {
		routes = []ReverseBlob{}
	}
	var resp ReverseRegisterResponse
	if err := a.do(ctx, "/helper/reverse/register", reverseRegisterRequest{Routes: routes}, &resp); err != nil {
		return nil, fmt.Errorf("reverse register: %w", err)
	}
	return &resp, nil
}

// Deregister removes this device's reverse routes.
func (a *ReverseAPI) Deregister(ctx context.Context) error {
	if err := a.do(ctx, "/helper/reverse/deregister", struct{}{}, nil); err != nil {
		return fmt.Errorf("reverse deregister: %w", err)
	}
	return nil
}

// Routes returns the reverse routes of the pairings in which this device
// helps.
func (a *ReverseAPI) Routes(ctx context.Context) (*ReverseRoutesResponse, error) {
	var resp ReverseRoutesResponse
	if err := a.do(ctx, "/helper/reverse/routes", struct{}{}, &resp); err != nil {
		return nil, fmt.Errorf("reverse routes: %w", err)
	}
	return &resp, nil
}

// reverseRequestBuilt, when set by a test, runs after a request is built.
var reverseRequestBuilt func()

func (a *ReverseAPI) do(ctx context.Context, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	// Kindling records its attempts on the span in the request's context, and
	// a helper call, or a redirect from one, must not show up in any trace.
	ctx, cancel := context.WithTimeout(traces.Untraced(ctx), reverseTimeout)
	defer cancel()
	r, err := common.NewRequestWithHeaders(ctx, http.MethodPost, a.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(common.DeviceIDHeader, a.deviceID)
	if reverseRequestBuilt != nil {
		reverseRequestBuilt()
	}
	// A stale address would make lantern-cloud advertise routes to the old
	// network; without it, lantern-cloud uses the address it sees. The
	// address and its network are read together, so a lookup landing after
	// the request was built cannot pass off the copied address as fresh.
	r.Header.Del(common.ClientIPHeader)
	if ip := common.FreshPublicIP(); ip != "" {
		r.Header.Set(common.ClientIPHeader, ip)
	}
	if val := settings.GetString(settings.FeatureOverridesKey); val != "" {
		r.Header.Set("X-Lantern-Feature-Override", val)
	}
	resp, err := a.httpClient.Do(r)
	if err != nil {
		// net/http errors quote the URL; keep only a cancellation cause.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("send: %w", ctxErr)
		}
		return errors.New("send failed")
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrReverseDisabled
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, maxReverseErrLen))
		text := strings.ToValidUTF8(strings.TrimSpace(string(buf)), "")
		return &ReverseAPIError{Status: resp.StatusCode, Body: text}
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxReverseBody)).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
