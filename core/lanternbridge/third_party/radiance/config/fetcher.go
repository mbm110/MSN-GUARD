package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"slices"

	C "github.com/getlantern/common"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/getlantern/kindling"
	"github.com/getlantern/lantern-box/protocol"

	"github.com/getlantern/radiance/account"
	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/env"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/internal/hostaccess"
	"github.com/getlantern/radiance/log"
	"github.com/getlantern/radiance/traces"
)

const tracerName = "github.com/getlantern/radiance/config"

type Fetcher interface {
	// fetchConfig fetches the configuration from the server. Nil is returned if no new config is available.
	// It returns an error if the request fails.
	// preferred is used to select the server location.
	// If preferred is empty, the server will select the best location.
	// The lastModified time is used to check if the configuration has changed since the last request.
	fetchConfig(ctx context.Context, preferred common.PreferredLocation, wgPublicKey string) ([]byte, error)
}

// fetcher is responsible for fetching the configuration from the server.
type fetcher struct {
	lastModified time.Time
	locale       string
	etag         string
	baseURL      string
	apiClient    *account.Client
	httpClient   *http.Client

	hasGlobalIPv6 func() bool
}

// newFetcher creates a new fetcher with the given http client.
func newFetcher(locale string, apiClient *account.Client, httpClient *http.Client) Fetcher {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: common.DefaultHTTPTimeout}
	}
	return &fetcher{
		lastModified: time.Time{},
		locale:       locale,
		baseURL:      common.GetBaseURL(),
		apiClient:    apiClient,
		httpClient:   httpClient,

		hasGlobalIPv6: common.HasGlobalIPv6,
	}
}

// fetchConfig fetches the configuration from the server. Nil is returned if no new config is available.
func (f *fetcher) fetchConfig(ctx context.Context, preferred common.PreferredLocation, wgPublicKey string) ([]byte, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "config_fetcher.fetchConfig")
	defer span.End()
	// If we don't have a user ID or token, create a new user.
	if err := f.ensureUser(ctx); err != nil {
		return nil, fmt.Errorf("error creating user: %w", err)
	}
	// Advertise that we honor NonSelectableOutbounds (merge server-declared infra
	// outbounds but keep them out of the proxy-selection groups) so the server can
	// gate such outbounds on the capability rather than the client version.
	// Advertise UnboundedTuning because our lantern-box's Unbounded outbound
	// accepts a "tuning" option, which the server withholds from older clients.
	// Advertise OutlineSmartDialer only with lantern-box v0.0.219 or later,
	// whose outline outbound accepts the server's smart-dialer config and
	// dials a rule-set download's host.
	// Advertise UnboundedDirectExitObfs because our lantern-box (v0.0.240 or
	// later) takes only Salamander-obfuscated direct exits and its
	// direct_exit option accepts pool_allowlist, which the server withholds
	// from older clients: sing-box rejects unknown fields. The server no
	// longer sends anything for the plain UnboundedDirectExit.
	capabilities := []string{C.CapabilityNonSelectableOutbounds, C.CapabilityUnboundedTuning, C.CapabilityOutlineSmartDialer, C.CapabilityUnboundedDirectExitObfs}
	if f.hasGlobalIPv6() {
		capabilities = append(capabilities, C.CapabilityIPv6)
	}
	confReq := C.ConfigRequest{
		SingboxVersion: singVersion(),
		Platform:       common.Platform,
		AppName:        common.Name,
		DeviceID:       settings.GetString(settings.DeviceIDKey),
		UserID:         fmt.Sprintf("%d", settings.GetInt64(settings.UserIDKey)),
		ProToken:       settings.GetString(settings.TokenKey),
		WGPublicKey:    wgPublicKey,
		Backend:        C.SINGBOX,
		Locale:         f.locale,
		Protocols:      supportedProtocols(),
		Capabilities:   capabilities,
	}
	if preferred.Country != "" {
		confReq.PreferredLocation = &preferred
	}
	buf, err := json.Marshal(&confReq)
	if err != nil {
		return nil, fmt.Errorf("marshal config request: %w", err)
	}
	addPayloadToSpan(ctx, confReq)

	slog.Debug(
		"sending config request",
		"platform", confReq.Platform,
		"locale", confReq.Locale,
		"protocol_count", len(confReq.Protocols),
		"capability_count", len(confReq.Capabilities),
	)
	buf, err = f.send(ctx, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if buf == nil { // no new config available
		return nil, nil
	}
	slog.Log(nil, log.LevelTrace, "received config", "bytes", len(buf))

	f.lastModified = time.Now()
	return buf, nil
}

func addPayloadToSpan(ctx context.Context, req C.ConfigRequest) {
	span := trace.SpanFromContext(ctx)
	// IDs, account tokens, device IDs, and WireGuard keys do not belong in
	// traces, even in abbreviated form. The remaining fields are enough to
	// diagnose client compatibility and request-shaping problems.
	req.UserID = ""
	req.ProToken = ""
	req.DeviceID = ""
	req.WGPublicKey = ""

	b, _ := json.Marshal(req)
	span.SetAttributes(attribute.String("http.request.body", string(b)))
}

func (f *fetcher) ensureUser(ctx context.Context) error {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "config_fetcher.ensureUser")
	defer span.End()
	if settings.GetInt64(settings.UserIDKey) == 0 || settings.GetString(settings.TokenKey) == "" {
		if f.apiClient == nil {
			slog.Error("API client is nil, cannot create new user")
			span.RecordError(errors.New("API client is nil"))
			return errors.New("API client is nil")
		}
		_, err := f.apiClient.NewUser(ctx)
		if err != nil {
			slog.Error("Failed to create new user", "error", err)
			span.RecordError(err)
			return fmt.Errorf("failed to create new user: %w", err)
		} else {
			slog.Info("Created new user")
		}
	}
	return nil
}

// send sends a request to the server with the given body and returns the response.
func (f *fetcher) send(ctx context.Context, body io.Reader) ([]byte, error) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, "config_fetcher.send")
	defer span.End()
	req, err := common.NewRequestWithHeaders(ctx, http.MethodPost, f.baseURL+"/config-new", body)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	// /config-new is POST-shaped (request carries last-known etag/version
	// + client metadata in the body) but is semantically a read-only
	// fetch — no server-side state mutates. Tag it idempotent so kindling's
	// raceTransport falls back to the next transport on transport-level
	// errors and 5xx, the same way it does for GET/HEAD. Without this, a
	// single fronting CDN returning 5xx (e.g., during a localized block)
	// would fail the whole fetch instead of being routed around.
	req.Header.Set(kindling.IdempotentHeader, "1")

	if val := env.GetString(env.Country); val != "" {
		slog.Info("Setting x-lantern-client-country header", "country", val)
		req.Header.Set("x-lantern-client-country", val)
	}
	if val := settings.GetString(settings.FeatureOverridesKey); val != "" {
		slog.Info("Setting X-Lantern-Feature-Override header", "features", val)
		req.Header.Set("X-Lantern-Feature-Override", val)
	}

	// Note that on the first run, lastModified is zero, so the server will return the latest config.
	req.Header.Set("If-Modified-Since", f.lastModified.Format(http.TimeFormat))
	if f.etag != "" {
		req.Header.Set("If-None-Match", f.etag)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("could not send request: %w", err))
	}
	defer resp.Body.Close()

	if etag := resp.Header.Get("ETag"); etag != "" {
		f.etag = etag
	}

	// Note that Go's HTTP library should automatically have decompressed the response here.
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, traces.RecordError(ctx, fmt.Errorf("could not read response body: %w", err))
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return buf, nil
	case http.StatusPartialContent:
		return buf, nil
	case http.StatusNotModified:
		slog.Debug("Config is not modified")
		return nil, nil
	case http.StatusNoContent:
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected status code: %d. %s", resp.StatusCode, buf)
	}
}

// singVersion returns the version of the sing-box module.
func singVersion() string {
	// First look for the sagernet/sing-box module version, and if it's not found, look for the getlantern/sing-box module version.
	singVersion, err := moduleVersion("github.com/sagernet/sing-box", "github.com/getlantern/sing-box")
	if err != nil {
		singVersion = "unknown"
	}
	slog.Debug("sing-box version", "version", singVersion)
	return singVersion
}

func moduleVersion(modulePath ...string) (string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", fmt.Errorf("could not read build info")
	}

	for _, mod := range info.Deps {
		if slices.Contains(modulePath, mod.Path) {
			return mod.Version, nil
		}
	}

	return "", fmt.Errorf("module %s not found", modulePath)
}

func supportedProtocols() []string {
	return slices.DeleteFunc(slices.Clone(protocol.SupportedProtocols()), func(p string) bool {
		return !hostaccess.TypeAllowed(p)
	})
}
