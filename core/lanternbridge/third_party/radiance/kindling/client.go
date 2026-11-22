// Package kindling provides a wrapper around the kindling library to create an HTTP client with
// various transports (domain fronting, AMP, DNS tunneling, proxyless) from a shared kindling instance.
package kindling

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/getlantern/kindling"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/getlantern/radiance/bypass"
	"github.com/getlantern/radiance/common"
	"github.com/getlantern/radiance/common/reporting"
	"github.com/getlantern/radiance/common/settings"
	"github.com/getlantern/radiance/internal/logsafe"
	"github.com/getlantern/radiance/kindling/fronted"
	radiancesmart "github.com/getlantern/radiance/kindling/smart"
	soartunnel "github.com/getlantern/radiance/kindling/soar"
	"github.com/getlantern/radiance/traces"
)

// TransportName identifies a transport in EnabledTransports.
type TransportName = kindling.TransportName

// Transport names re-exported so callers configure transports through this
// package without importing the upstream kindling library directly.
const (
	TransportAMP         = kindling.TransportAMP
	TransportDomainfront = kindling.TransportDomainfront
	TransportDNSTunnel   = kindling.TransportDNSTunnel
	TransportSmart       = kindling.TransportSmart
)

var (
	mu          sync.Mutex
	initialized bool
	k           *Client
	// paused is the current pause state, kept here because a pause can arrive
	// with no client to receive it.
	paused bool
	// EnabledTransports gates which transports NewKindling wires up. AMP is
	// parked off for every country; its builder stays wired behind the flag so
	// turning it back on is a one-line change. The DNS tunnel (Soar) also needs
	// a build carrying a Soar server, and kindling races it only after every
	// other transport fails.
	//
	// A var rather than constants because cmd/kindling-tester rewrites it to
	// isolate a single transport, as does TestNewClient. Production code sets
	// it once, here: nothing toggles a transport at runtime.
	EnabledTransports = map[kindling.TransportName]bool{
		kindling.TransportDNSTunnel:   true,
		kindling.TransportAMP:         false,
		kindling.TransportSmart:       true,
		kindling.TransportDomainfront: true,
	}
	defaultTransportClone = http.DefaultTransport.(*http.Transport).Clone()

	transport http.RoundTripper
)

func initKindling() {
	newK, err := NewKindling(settings.GetString(settings.DataPathKey))
	if err != nil {
		slog.Error("failed to create kindling client", slog.Any("error", err))
	}
	if newK != nil {
		setClient(newK)
		transport = traces.NewRoundTripper(traces.NewHeaderAnnotatingRoundTripper(newK.NewHTTPClient().Transport))
	} else {
		slog.Warn("kindling unavailable, using default transport clone")
		transport = traces.NewRoundTripper(traces.NewHeaderAnnotatingRoundTripper(defaultTransportClone))
	}
}

func Init() {
	go ensureInit()
}

func ensureInit() http.RoundTripper {
	mu.Lock()
	defer mu.Unlock()
	if !initialized {
		initKindling()
		initialized = true
	}
	return transport
}

// HTTPClient returns an HTTP client whose transport blocks on first use
// until kindling is initialized.
func HTTPClient() *http.Client {
	return &http.Client{
		Timeout:   common.KindlingHTTPTimeout,
		Transport: readyTransport{},
	}
}

type readyTransport struct{}

func (readyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return ensureInit().RoundTrip(req)
}

// Close stops any in-flight config fetches, releases kindling transports, and
// re-arms the package so the next Init or HTTPClient use rebuilds the stack.
func Close() error {
	// Mobile constructs a new LocalBackend in the same process after the system
	// extension stops, so Close must not be terminal.
	mu.Lock()
	defer mu.Unlock()
	if k != nil {
		if err := k.Close(); err != nil {
			slog.Error("failed to close kindling transports", slog.Any("error", err))
		}
		k = nil
	}
	transport = nil
	initialized = false
	// Wakes only ever come from a live tunnel, so a pause must not outlive one.
	paused = false
	return nil
}

// SetNetworkPaused sets whether the shared transports' background work is paused.
//
// The state also applies to clients installed later, until Close resets it.
// Updates from canceled contexts are ignored.
func SetNetworkPaused(ctx context.Context, next bool) {
	mu.Lock()
	defer mu.Unlock()
	// Cancellation must be checked under mu to reject updates arriving after teardown.
	if ctx.Err() != nil || paused == next {
		return
	}
	paused = next
	if k != nil {
		k.applyPauseLocked(next)
	}
}

// setClient installs c as the shared instance, applying any pause held at
// install time. The caller must hold mu.
func setClient(c *Client) {
	k = c
	if c != nil && paused {
		c.applyPauseLocked(true)
	}
}

const tracerName = "github.com/getlantern/radiance/kindling"

// pausable transports must tolerate repeated Pause and Resume calls.
type pausable interface {
	Pause()
	Resume()
}

// Client is a kindling instance together with the transport resources its
// construction created (config updaters, fronted state).
type Client struct {
	kindling.Kindling
	cancel    context.CancelFunc
	closers   []func() error
	pausers   []pausable
	closeOnce sync.Once
}

// applyPauseLocked must be called with mu held.
func (c *Client) applyPauseLocked(pause bool) {
	for _, p := range c.pausers {
		if pause {
			p.Pause()
		} else {
			p.Resume()
		}
	}
}

// Close cancels the transports' config updaters and releases their resources.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		var errs []error
		for _, cl := range c.closers {
			errs = append(errs, cl())
		}
		err = errors.Join(errs...)
	})
	return err
}

// NewKindling builds a kindling client. On error, any partially built
// transport state is released before returning.
func NewKindling(dataDir string) (*Client, error) {
	logger := &slogWriter{Logger: slog.Default()}

	ctx, span := otel.Tracer(tracerName).Start(
		context.Background(),
		"NewKindling",
		trace.WithAttributes(attribute.String("data_path", dataDir)),
	)
	defer span.End()

	if common.Stage() {
		// Staging runs proxyless-only; fronted client failures against staging
		// hosts otherwise obscure the backend behavior we want to test.
		newK, err := kindling.NewKindling("radiance",
			kindling.WithPanicListener(reporting.PanicListener),
			kindling.WithLogWriter(logger),
			kindling.WithStreamDialer(bypass.StreamDialer()),
			kindling.WithSmartDialerConfig(radiancesmart.DialerConfig),
			kindling.WithRaceObserver(recordRace),
			// "pro-server" calls still target api.getiantem.org; everything
			// else uses df.iantem.io. freddie.iantem.io is Unbounded's
			// signaling server, which staging shares with production.
			kindling.WithProxyless("df.iantem.io", "api.getiantem.org", "api.staging.iantem.io", "freddie.iantem.io"),
		)
		if err != nil {
			return nil, err
		}
		return &Client{Kindling: newK}, nil
	}

	var closers []func() error
	var pausers []pausable
	kindlingOptions := []kindling.Option{
		kindling.WithPanicListener(reporting.PanicListener),
		kindling.WithLogWriter(logger),
		kindling.WithStreamDialer(bypass.StreamDialer()),
		kindling.WithSmartDialerConfig(radiancesmart.DialerConfig),
		kindling.WithRaceObserver(recordRace),
	}

	updaterCtx, cancel := context.WithCancel(ctx)
	if enabled := EnabledTransports[kindling.TransportDomainfront]; enabled {
		f, err := fronted.NewFronted(updaterCtx, filepath.Join(dataDir, "fronted_cache.json"), logger)
		if err != nil {
			slog.Error("failed to create fronted client", slog.Any("error", err))
			span.RecordError(err)
		}
		if f != nil {
			closers = append(closers, func() error { f.Close(); return nil })
			pausers = append(pausers, f)
			kindlingOptions = append(kindlingOptions, kindling.WithDomainFronting(f))
		}
	}

	if enabled := EnabledTransports[kindling.TransportAMP]; enabled {
		ampClient, err := fronted.NewAMPClient(updaterCtx, dataDir, logger)
		if err != nil {
			slog.Error("failed to create amp client", slog.Any("error", err))
			span.RecordError(err)
		}
		if ampClient != nil {
			kindlingOptions = append(kindlingOptions, kindling.WithAMPCache(ampClient))
		}
	}

	if enabled := EnabledTransports[kindling.TransportSmart]; enabled {
		// "pro-server" calls still target api.getiantem.org; everything
		// else uses df.iantem.io, which proxyless reaches as df.getiantem.org:
		// Google's edge 403s Iranian clients on df.iantem.io, while the same
		// origin behind Cloudflare gets through. freddie.iantem.io is
		// Unbounded's signaling server.
		kindlingOptions = append(kindlingOptions,
			kindling.WithProxyless("df.getiantem.org", "api.getiantem.org", "freddie.iantem.io"),
			kindling.WithProxylessAliases(map[string]string{"df.iantem.io": "df.getiantem.org"}),
		)
	}

	if enabled := EnabledTransports[kindling.TransportDNSTunnel]; enabled && soartunnel.Configured() {
		sc, err := soartunnel.New(dataDir)
		if err != nil {
			slog.Error("failed to create soar dns tunnel", slog.Any("error", err))
			span.RecordError(err)
		} else {
			closers = append(closers, sc.Close)
			kindlingOptions = append(kindlingOptions, kindling.WithDNSTunnel(sc))
		}
	}

	newK, err := kindling.NewKindling("radiance", kindlingOptions...)
	if err != nil {
		errs := []error{err}
		cancel()
		for _, cl := range closers {
			errs = append(errs, cl())
		}
		return nil, errors.Join(errs...)
	}
	return &Client{
		Kindling: newK,
		cancel:   cancel,
		closers:  closers,
		pausers:  pausers,
	}, nil
}

type slogWriter struct {
	*slog.Logger
}

func (w *slogWriter) Write(p []byte) (n int, err error) {
	s := strings.TrimSpace(string(p))
	w.Info(logsafe.StripQueries(s))
	return len(p), nil
}

// SetKindling installs a test-supplied kindling instance and claims
// initialization — call it before Init or the first request through
// HTTPClient, or it will silently no-op. The package Close closes the
// installed instance.
func SetKindling(c *Client) {
	mu.Lock()
	defer mu.Unlock()
	if initialized {
		return
	}
	setClient(c)
	if c != nil {
		transport = traces.NewRoundTripper(traces.NewHeaderAnnotatingRoundTripper(c.NewHTTPClient().Transport))
	} else {
		transport = traces.NewRoundTripper(traces.NewHeaderAnnotatingRoundTripper(defaultTransportClone))
	}
	initialized = true
}
