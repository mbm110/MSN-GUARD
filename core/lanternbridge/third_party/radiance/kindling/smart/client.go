// Package smart contains a HTTP client with smart transport used by other
// methods to fetch config updates
package smart

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"sync"

	"github.com/getlantern/kindling"
	"github.com/getlantern/radiance/bypass"
	"github.com/getlantern/radiance/traces"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/getlantern/radiance/kindling/smart"

// DialerConfig is a copy of kindling's smart_dialer_config.yml with the
// `system: {}` DNS entry removed, which is the one divergence a resync has to
// carry over. The outline-sdk smart strategy rejects any base StreamDialer that
// isn't *transport.TCPDialer when the system resolver is selected, which the
// bypass dialer can't satisfy. DoH entries route every probe through the
// supplied StreamDialer instead, which is what we want anyway — system DNS uses
// OS routing tables and would loop back through the VPN TUN we're trying to
// bypass.
//
//go:embed smart_dialer_config.yml
var DialerConfig []byte

// newSmartTransport is a test seam: a real strategy search needs network
// reachability that tests don't have.
var newSmartTransport = func(logWriter io.Writer, host string) (http.RoundTripper, error) {
	trans, err := kindling.NewSmartHTTPTransportWithConfig(logWriter, DialerConfig, bypass.StreamDialer(), nil, host)
	if err != nil {
		return nil, err
	}
	if trans == nil {
		return nil, fmt.Errorf("no smart transport for %q", host)
	}
	return trans, nil
}

// NewHTTPClientWithSmartTransport returns an HTTP client that reaches each
// config URL's host through its own Outline smart dialer. At least one URL with
// a host is required.
//
// One dialer per host rather than one dialer covering all of them: the strategy
// search is conjunctive, so a single dialer given several hosts succeeds only if
// one strategy unblocks every one of them, and a host that is blocked outright
// then takes the reachable ones down with it.
func NewHTTPClientWithSmartTransport(logWriter io.Writer, addresses ...string) (*http.Client, error) {
	lz, err := newLazyDialingRoundTripper(logWriter, addresses...)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: traces.NewRoundTripper(lz)}, nil
}

// newLazyDialingRoundTripper builds the per-host transports. Split out so tests
// can read which hosts have a search under way without unwrapping the client.
func newLazyDialingRoundTripper(logWriter io.Writer, addresses ...string) (*lazyDialingRoundTripper, error) {
	hosts, err := configHosts(addresses)
	if err != nil {
		return nil, err
	}
	byHost := make(map[string]*hostTransport, len(hosts))
	for i, host := range hosts {
		ht := &hostTransport{
			host:         host,
			logWriter:    logWriter,
			newTransport: newSmartTransport,
		}
		byHost[host] = ht
		// Only the primary searches up front. A search probes the whole strategy
		// space at once, and two running concurrently overran the iOS extension's
		// 50 MB jetsam cap. Fallbacks search on first use in roundTripper, paying
		// for it inside that caller's timeout — a cost borne only on the path
		// taken when the primary is already blocked.
		if i == 0 {
			ht.beginSearch()
		}
	}
	return &lazyDialingRoundTripper{hosts: hosts, byHost: byHost}, nil
}

// configHosts returns each address's host, in order and deduplicated.
func configHosts(addresses []string) ([]string, error) {
	seen := make(map[string]bool, len(addresses))
	hosts := make([]string, 0, len(addresses))
	for _, address := range addresses {
		u, err := url.Parse(address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse URL %q: %w", address, err)
		}
		// Hostname() drops any :port; skip empties (e.g. scheme-less URLs) and
		// dedup so a shared host isn't dialed through two dialers.
		host := u.Hostname()
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no valid config host among %v", addresses)
	}
	return hosts, nil
}

// lazyDialingRoundTripper routes each request to its own host's transport, so a
// host that never becomes reachable costs only the requests aimed at it.
//
// byHost is written only during construction, so reads need no lock; each entry
// guards its own transport.
type lazyDialingRoundTripper struct {
	hosts  []string
	byHost map[string]*hostTransport
}

var _ http.RoundTripper = (*lazyDialingRoundTripper)(nil)

func (lz *lazyDialingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	ht := lz.transportFor(host)
	ctx, span := otel.Tracer(tracerName).Start(
		req.Context(),
		"lazy_dialing_round_trip",
		trace.WithAttributes(
			attribute.String("domain", host),
			attribute.String("transport_host", ht.host),
			attribute.StringSlice("domains", lz.hosts),
		),
	)
	defer span.End()

	trans, err := ht.roundTripper(ctx)
	if err != nil {
		// A caller that gave up learned nothing about the host, so don't report
		// its own cancellation as this host being unreachable.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, traces.RecordError(ctx, fmt.Errorf("could not create smart transport for %q: %w", ht.host, err))
	}
	res, err := trans.RoundTrip(req.WithContext(ctx))
	if err != nil {
		traces.RecordError(ctx, err, trace.WithStackTrace(true))
	}
	return res, err
}

// transportFor returns host's transport, falling back to the first configured
// host's: one tuned for a sibling config source is a better guess than failing
// the request outright.
func (lz *lazyDialingRoundTripper) transportFor(host string) *hostTransport {
	if ht, ok := lz.byHost[host]; ok {
		return ht
	}
	return lz.byHost[lz.hosts[0]]
}

// hostTransport holds one host's smart transport, built by a strategy search and
// reused once it lands. Searches are single-flight: concurrent callers join the
// one already running rather than starting their own.
type hostTransport struct {
	host      string
	logWriter io.Writer

	// newTransport is captured at construction rather than read from the
	// package var, so that a search still running in the background can't race
	// a test restoring the seam.
	newTransport func(logWriter io.Writer, host string) (http.RoundTripper, error)

	mu       sync.Mutex
	trans    http.RoundTripper
	inFlight *pendingSearch
}

// pendingSearch is one attempt at building a host's transport. trans and err are
// written before done is closed, so a caller that has received from done may
// read them without the lock.
type pendingSearch struct {
	done  chan struct{}
	trans http.RoundTripper
	err   error
}

// roundTripper returns the transport for this host, starting a strategy search
// on first use and joining one already under way otherwise. ctx bounds only the
// wait — the search itself takes no context and runs to completion on its own
// goroutine, so work a caller gave up on still serves whoever comes next.
//
// A failed search is deliberately not remembered: this requires callers to
// retry on their own schedule, in exchange for letting a host blocked at first
// contact recover without a restart.
func (ht *hostTransport) roundTripper(ctx context.Context) (http.RoundTripper, error) {
	trans, search := ht.beginSearch()
	if trans != nil {
		return trans, nil
	}
	select {
	case <-search.done:
		return search.trans, search.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// beginSearch hands the search back rather than waiting on it, so that the
// caller who starts one can abandon it on its own context just as a caller who
// joins one can.
func (ht *hostTransport) beginSearch() (http.RoundTripper, *pendingSearch) {
	ht.mu.Lock()
	defer ht.mu.Unlock()
	if ht.trans != nil {
		return ht.trans, nil
	}
	if ht.inFlight == nil {
		ht.inFlight = &pendingSearch{done: make(chan struct{})}
		go ht.runSearch(ht.inFlight)
	}
	return nil, ht.inFlight
}

// runSearch clears inFlight before releasing anyone waiting on search, so a
// caller arriving in that window starts a fresh search rather than joining a
// finished one. The entire release path is deferred because recover cannot stop
// a runtime.Goexit — a test helper's t.Fatal, say — from unwinding this
// goroutine: even then the search must report an error rather than (nil, nil),
// clear inFlight so the next caller starts fresh, and only then release.
func (ht *hostTransport) runSearch(search *pendingSearch) {
	defer func() {
		if search.trans == nil && search.err == nil {
			search.err = fmt.Errorf("strategy search for %q exited without a result", ht.host)
		}
		ht.mu.Lock()
		if search.err == nil {
			ht.trans = search.trans
		}
		ht.inFlight = nil
		ht.mu.Unlock()
		close(search.done)
	}()

	search.trans, search.err = ht.buildTransport()
	if search.err != nil {
		slog.Warn("smart dialer found no working strategy", "host", ht.host, "error", search.err)
	}
}

// buildTransport turns a panic into an error: the search runs on a goroutine of
// its own, where a panic would take the process down with no caller in a
// position to intercept it, and a host whose search blows up should cost only
// that host.
func (ht *hostTransport) buildTransport() (trans http.RoundTripper, err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("smart dialer strategy search panicked",
				"host", ht.host, "panic", r, "stack", string(debug.Stack()))
			//logleak:ok recovered panic value
			err = fmt.Errorf("strategy search panicked: %v", r)
		}
	}()
	return ht.newTransport(ht.logWriter, ht.host)
}
